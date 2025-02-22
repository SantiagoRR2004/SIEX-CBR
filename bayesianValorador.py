import valorador
import cbrkit
from skopt import BayesSearchCV
from tqdm import tqdm
from sklearn.base import BaseEstimator
from sklearn.model_selection import PredefinedSplit
from typing import Dict
import numpy as np
import copy
from cbrkit.typing import (
    Casebase,
    KeyType,
    SimMap,
    SimType,
    ValueType,
)
from cbrkit.sim import AttributeValueSim
import itertools
import os


class ClassWithValue:
    """
    We need to create a class that has
    a value attribute to be able
    to use the similarity function
    """

    def __init__(self, value: float) -> None:
        """
        Constructor of the class

        The value should be between 0 and 1

        Args:
            - value: float

        Returns:
            - None
        """
        self.value = value


def similarity(
    x_map: Casebase[KeyType, ValueType], y: ValueType
) -> SimMap[KeyType, AttributeValueSim[SimType]]:
    """
    Function acts as it calculates the similarity between the cases

    It replicates wrapped_func from cbrkit.sim._attribute_value

    It actually returns a dictionary with the keys being
    the keys of the cases and the values being an instance
    of an

    Args:
        - x_map: Casebase[KeyType, ValueType]
        - y: ValueType

    Returns:
        - SimMap[KeyType, AttributeValueSim[SimType]]
    """
    values = {}
    for key in x_map.keys():
        values[key] = ClassWithValue(1.0)
    return values


class BayesianValorador(valorador.Valorador, BaseEstimator):
    def __init__(
        self,
        base_de_casos: Dict[int, dict],
        *,
        cweSim: str = None,
        assignerSim: str = None,
        keywordsSim: str = None,
        affectedProductsSim: str = None,
        cweWeight: float = 1.0,
        assignerWeight: float = 1.0,
        keywordsWeight: float = 1.0,
        affectedProductsWeight: float = 1.0,
        umbralScore: int = 1,
        num_casos_similares: int = 100,
        taxonomia: str = "./datos/jerarquia_cwe_1000.yaml",
        debug: bool = False,
    ):
        """
        Constructor of the BayesianValorador class

        We don't want to use multicore because we already
        use parallelization in the bayesian search

        Args:
            - base_de_casos: Dict[int, dict]
            - cweSim: str. The similarity function to use for the CWE
            - assignerSim: str. The similarity function to use for the assigner
            - keywordsSim: str. The similarity function to use for the keywords
            - affectedProductsSim: str. The similarity function to use for the affectedProducts
            - cweWeight: float The weight to use for the CWE
            - assignerWeight: float  The weight to use for the assigner
            - keywordsWeight: float  The weight to use for the keywords
            - affectedProductsWeight: float  The weight to use for the affectedProducts
            - umbralScore: int
            - num_casos_similares: int
            - taxonomia: str
            - debug: bool

        Returns:
            - None
        """
        self.debug = debug
        self.taxonomia = taxonomia
        self.num_casos_similares = num_casos_similares
        self.cweSim = cweSim
        self.assignerSim = assignerSim
        self.keywordsSim = keywordsSim
        self.affectedProductsSim = affectedProductsSim
        self.cweWeight = cweWeight
        self.assignerWeight = assignerWeight
        self.keywordsWeight = keywordsWeight
        self.affectedProductsWeight = affectedProductsWeight
        super().__init__(
            base_de_casos=base_de_casos,
            umbralScore=umbralScore,
            num_casos_similares=num_casos_similares,
            taxonomia=taxonomia,
            debug=debug,
            multiCore=False,
        )

    def inicializar_retriever(
        self, num_casos_similares: int, taxonomia_cwe: str
    ) -> cbrkit.retrieval.RetrieverFunc:
        """
        Function that initializes the retriever.

        It tries to initialize the attributes with the
        similarity functions that have been given
        when creating the object.

        If no similarity functions have been given, it
        will use an empty one that will always return 1.0

        Args:
            - num_casos_similares: int. The number of similar cases to retrieve
            - taxonomia_cwe: str. The path to the CWE taxonomy

        Returns:
            - cbrkit.retrieval.RetrieverFunc. The retriever function
        """
        attributes = {}

        attributes = self.inicializarCWE(attributes, taxonomia_cwe)

        attributes = self.inicializarAssigner(attributes)

        attributes = self.inicializarKeywords(attributes)

        attributes = self.inicializarAffectedProducts(attributes)

        # Check if attributes have been set
        if attributes and (
            self.cweWeight
            or self.assignerWeight
            or self.keywordsWeight
            or self.affectedProductsWeight
        ):
            # Create the similarity function if they exist
            case_similarity = cbrkit.sim.attribute_value(
                attributes=attributes,
                aggregator=cbrkit.sim.aggregator(
                    pooling="mean",
                    pooling_weights={
                        "cwe": self.cweWeight,
                        "assigner": self.assignerWeight,
                        "keywords": self.keywordsWeight,
                        "affected_products": self.affectedProductsWeight,
                    },
                ),
            )

            # Crear un objeto de recuperación
            retriever = cbrkit.retrieval.build(
                case_similarity, limit=num_casos_similares
            )
        # No attributes have been set
        else:
            retriever = cbrkit.retrieval.build(
                similarity_func=similarity,
                limit=num_casos_similares,
            )

        return retriever

    def inicializarCWE(self, attributes: dict, taxonomia_cwe: str) -> dict:
        """
        Function that initializes the CWE attribute

        It allows:
            - None
            - wu_palmer
            - path_steps
            - auto_weightsOptimistic
            - auto_weightsAverage
            - auto_weightsPessimistic
            - node_levelsOptimistic
            - node_levelsAverage
            - node_levelsPessimistic

        We don't use user_weights because they aren't
        defined in the CWE taxonomy so it would be
        the same as using auto_weights

        Args:
            - attributes: dict. The attributes dictionary
            - taxonomia_cwe: str. The path to the CWE taxonomy

        Returns:
            - None
        """
        if self.cweSim is not None:
            if self.cweSim == "wu_palmer":
                cwe_similarity = cbrkit.sim.strings.taxonomy.load(
                    taxonomia_cwe, cbrkit.sim.strings.taxonomy.wu_palmer()
                )
            elif self.cweSim == "path_steps":
                cwe_similarity = cbrkit.sim.strings.taxonomy.load(
                    taxonomia_cwe, cbrkit.sim.strings.taxonomy.path_steps()
                )
            elif self.cweSim == "auto_weightsOptimistic":
                cwe_similarity = cbrkit.sim.strings.taxonomy.load(
                    taxonomia_cwe,
                    cbrkit.sim.strings.taxonomy.auto_weights("optimistic"),
                )
            elif self.cweSim == "auto_weightsAverage":
                cwe_similarity = cbrkit.sim.strings.taxonomy.load(
                    taxonomia_cwe,
                    cbrkit.sim.strings.taxonomy.auto_weights("average"),
                )
            elif self.cweSim == "auto_weightsPessimistic":
                cwe_similarity = cbrkit.sim.strings.taxonomy.load(
                    taxonomia_cwe,
                    cbrkit.sim.strings.taxonomy.auto_weights("pessimistic"),
                )
            elif self.cweSim == "node_levelsOptimistic":
                cwe_similarity = cbrkit.sim.strings.taxonomy.load(
                    taxonomia_cwe,
                    cbrkit.sim.strings.taxonomy.node_levels("optimistic"),
                )
            elif self.cweSim == "node_levelsAverage":
                cwe_similarity = cbrkit.sim.strings.taxonomy.load(
                    taxonomia_cwe,
                    cbrkit.sim.strings.taxonomy.node_levels("average"),
                )
            elif self.cweSim == "node_levelsPessimistic":
                cwe_similarity = cbrkit.sim.strings.taxonomy.load(
                    taxonomia_cwe,
                    cbrkit.sim.strings.taxonomy.node_levels("pessimistic"),
                )
            else:
                raise ValueError(f"El valor de cweSim={self.cweSim} no es válido")
            attributes["cwe"] = cwe_similarity

        return attributes

    def inicializarAssigner(self, attributes: dict) -> dict:
        """
        Function that initializes the Assigner attribute

        It allows:
            - None
            - levenshtein
            - jaro
            - jaro_winkler
            - ngram
            - regex

        We don't use glob because it would be the same
        as using regex because there are no wildcards.

        We also don't use table because we have no table
        to use.

        The three that use word vectors are not used
        because they take too long to calculate.

        Args:
            - attributes: dict. The attributes dictionary

        Returns:
            - None
        """
        if self.assignerSim is not None:
            if self.assignerSim == "levenshtein":
                assigner_similarity = cbrkit.sim.strings.levenshtein()
            elif self.assignerSim == "jaro":
                assigner_similarity = cbrkit.sim.strings.jaro()
            elif self.assignerSim == "jaro_winkler":
                assigner_similarity = cbrkit.sim.strings.jaro_winkler()
            elif self.assignerSim == "ngram":
                assigner_similarity = cbrkit.sim.strings.ngram(n=1)
            elif self.assignerSim == "regex":
                assigner_similarity = cbrkit.sim.strings.regex()
            else:
                raise ValueError(
                    f"El valor de assignerSim={self.assignerSim} no es válido"
                )

            attributes["assigner"] = assigner_similarity

        return attributes

    def inicializarKeywords(self, attributes: dict) -> dict:
        """
        Function that initializes the Keywords attribute

        It allows:
            - None
            - jaccard
            - smith_waterman

        We don't use dtw because we have strings and not
        time series.

        We can't use sequence_correctness because it needs two
        sequences with the same elements and it checks the order.
        We can't ensure that the lists of keywords have the same elements.

        We can't use isolated_mapping, mapping or sequence_mapping
        because they return the error:

            float division by zero


        Args:
            - attributes: dict. The attributes dictionary

        Returns:
            - None
        """
        if self.keywordsSim is not None:
            if self.keywordsSim == "jaccard":
                keywords_similarity = cbrkit.sim.collections.jaccard()
            elif self.keywordsSim == "smith_waterman":
                keywords_similarity = cbrkit.sim.collections.smith_waterman()
            else:
                raise ValueError(
                    f"El valor de keywordsSim={self.keywordsSim} no es válido"
                )
            attributes["keywords"] = keywords_similarity

        return attributes

    def inicializarAffectedProducts(self, attributes: dict) -> dict:
        """
        Function that initializes the AffectedProducts attribute

        It allows:
            - None
            - jaccard
            - smith_waterman
            - isolated_mappingLevenshtein
            - isolated_mappingJaro
            - isolated_mappingJaro_winkler
            - isolated_mappingNgram
            - mappingLevenshtein
            - mappingJaro
            - mappingJaro_winkler
            - mappingNgram
            - sequence_mappingLevenshtein
            - sequence_mappingJaro
            - sequence_mappingJaro_winkler
            - sequence_mappingNgram

        We don't use dtw because we have strings and not
        time series.

        We can't use sequence_correctness because it needs two
        sequences with the same elements and it checks the order.
        We can't ensure that the lists of keywords have the same elements.

        regex sometimes returns an error so we don't use it.

            re.error: nothing to repeat at position 15

        Args:
            - attributes: dict. The attributes dictionary

        Returns:
            - None
        """
        if self.affectedProductsSim is not None:
            if self.affectedProductsSim == "jaccard":
                affected_products_similarity = cbrkit.sim.collections.jaccard()
            elif self.affectedProductsSim == "smith_waterman":
                affected_products_similarity = cbrkit.sim.collections.smith_waterman()
            elif self.affectedProductsSim == "isolated_mappingLevenshtein":
                affected_products_similarity = cbrkit.sim.collections.isolated_mapping(
                    cbrkit.sim.strings.levenshtein()
                )
            elif self.affectedProductsSim == "isolated_mappingJaro":
                affected_products_similarity = cbrkit.sim.collections.isolated_mapping(
                    cbrkit.sim.strings.jaro()
                )
            elif self.affectedProductsSim == "isolated_mappingJaro_winkler":
                affected_products_similarity = cbrkit.sim.collections.isolated_mapping(
                    cbrkit.sim.strings.jaro_winkler()
                )
            elif self.affectedProductsSim == "isolated_mappingNgram":
                affected_products_similarity = cbrkit.sim.collections.isolated_mapping(
                    cbrkit.sim.strings.ngram(n=1)
                )
            elif self.affectedProductsSim == "mappingLevenshtein":
                affected_products_similarity = cbrkit.sim.collections.mapping(
                    cbrkit.sim.strings.levenshtein()
                )
            elif self.affectedProductsSim == "mappingJaro":
                affected_products_similarity = cbrkit.sim.collections.mapping(
                    cbrkit.sim.strings.jaro()
                )
            elif self.affectedProductsSim == "mappingJaro_winkler":
                affected_products_similarity = cbrkit.sim.collections.mapping(
                    cbrkit.sim.strings.jaro_winkler()
                )
            elif self.affectedProductsSim == "mappingNgram":
                affected_products_similarity = cbrkit.sim.collections.mapping(
                    cbrkit.sim.strings.ngram(n=1)
                )
            elif self.affectedProductsSim == "sequence_mappingLevenshtein":
                affected_products_similarity = cbrkit.sim.collections.sequence_mapping(
                    cbrkit.sim.strings.levenshtein()
                )
            elif self.affectedProductsSim == "sequence_mappingJaro":
                affected_products_similarity = cbrkit.sim.collections.sequence_mapping(
                    cbrkit.sim.strings.jaro()
                )
            elif self.affectedProductsSim == "sequence_mappingJaro_winkler":
                affected_products_similarity = cbrkit.sim.collections.sequence_mapping(
                    cbrkit.sim.strings.jaro_winkler()
                )
            elif self.affectedProductsSim == "sequence_mappingNgram":
                affected_products_similarity = cbrkit.sim.collections.sequence_mapping(
                    cbrkit.sim.strings.ngram(n=1)
                )
            else:
                raise ValueError(
                    f"El valor de affectedProductsSim={self.affectedProductsSim} no es válido"
                )

            attributes["affected_products"] = affected_products_similarity

        return attributes

    def fit(self, X=None, y=None) -> None:
        """
        Function that is necessary to implement the BayesSearchCV

        We reset the retriever with the new hyperparameters

        Args:
            - X
            - y

        Returns:
            - None
        """
        self.retriever = self.inicializar_retriever(
            self.num_casos_similares, self.taxonomia
        )

    def score(self, X=None, y=None) -> float:
        """
        Function that is necessary to implement the BayesSearchCV

        We calculate the score of the model.

        It is calculated as the mean of the absolute difference
        between the real score and the predicted score
        for every case in /datos/casos_a_resolver.json

        It is the neg_mean_absolute_error

        Args:
            - X
            - y

        Returns:
            - float. The neg_mean_absolute_error
        """
        casos_a_resolver = cbrkit.loaders.json("./datos/casos_a_resolver.json")
        realScores = []
        predictedScores = []

        # Need to make a deep copy of the base_de_casos
        # because it may add the cases to the base_de_casos
        initialCases = copy.deepcopy(self.base_de_casos)

        for caso in casos_a_resolver.values():
            caso_resuelto = self.ciclo_cbr(caso)
            realScores.append(caso_resuelto["_meta"]["score_real"])
            predictedScores.append(caso["_meta"]["score_predicho"])

        score = sum(abs(np.array(realScores) - np.array(predictedScores))) / len(
            casos_a_resolver
        )

        self.base_de_casos = initialCases

        return -score


def checkValidParams(
    paramSpace: Dict[str, list], base_de_casos: Dict[int, dict]
) -> None:
    """
    Function that checks if the parameters are valid

    It iterates over all possible combinations of the parameters

    Args:
        - paramSpace: Dict[str, list]. The parameters to check. They keys
            are the names of the parameters and the values are the possible
            values of the parameters
        - base_de_casos: Dict[int, dict]. The dataset to use

    Returns:
        - None
    """
    casos_a_resolver = cbrkit.loaders.json("./datos/casos_a_resolver.json")

    combinations = list(itertools.product(*paramSpace.values()))

    for combination in tqdm(combinations):

        try:
            model = BayesianValorador(
                base_de_casos=base_de_casos, **dict(zip(paramSpace.keys(), combination))
            )

            model.ciclo_cbr(casos_a_resolver[0])

        except Exception as e:
            print(f"Error with combination {dict(zip(paramSpace.keys(), combination))}")
            raise e


if __name__ == "__main__":
    nCores = os.cpu_count()

    base_casos = cbrkit.loaders.json("./datos/base_casos.json")

    """
    We don't have None in the parameters because
    there is already 0.0 in the weights.
    """

    paramSpace = {
        "cweSim": [
            "wu_palmer",
            "path_steps",
            "auto_weightsOptimistic",
            "auto_weightsAverage",
            "auto_weightsPessimistic",
            "node_levelsOptimistic",
            "node_levelsAverage",
            "node_levelsPessimistic",
        ],
        "assignerSim": ["levenshtein", "jaro", "jaro_winkler", "ngram", "regex"],
        "keywordsSim": ["jaccard", "smith_waterman"],
        "affectedProductsSim": [
            "jaccard",
            "smith_waterman",
            "isolated_mappingLevenshtein",
            "isolated_mappingJaro",
            "isolated_mappingJaro_winkler",
            "isolated_mappingNgram",
            "mappingLevenshtein",
            "mappingJaro",
            "mappingJaro_winkler",
            "mappingNgram",
            "sequence_mappingLevenshtein",
            "sequence_mappingJaro",
            "sequence_mappingJaro_winkler",
            "sequence_mappingNgram",
        ],
    }

    # checkValidParams(paramSpace, base_casos)

    """    
    Now we know that the parameters are valid,
    we can run the BayesSearchCV to find the best hyperparameters
    with the weights
    """

    # We add the weights to the parameters
    paramSpace["cweWeight"] = [0, 0.25, 0.5, 0.75, 1.0]
    paramSpace["assignerWeight"] = [0, 0.25, 0.5, 0.75, 1.0]
    paramSpace["keywordsWeight"] = [0, 0.25, 0.5, 0.75, 1.0]
    paramSpace["affectedProductsWeight"] = [0, 0.25, 0.5, 0.75, 1.0]

    model = BayesianValorador(base_de_casos=base_casos)

    # Calculate the maximum number of iterations
    maxCombs = np.prod([len(paramSpace[key]) for key in paramSpace.keys()])

    nCombinations = 256

    # If the number of iterations is greater than the maximum number of iterations, we set it to the maximum number of iterations
    if nCombinations > maxCombs:
        nCombinations = maxCombs

    # Create a dummy dataset
    data = [1, 1]

    # Create a PredefinedSplit that so it only does one iteration
    ps = PredefinedSplit([-1, 0])

    bayes_search = BayesSearchCV(
        estimator=model,
        search_spaces=paramSpace,
        cv=ps,
        n_iter=nCombinations,
        random_state=0,
        n_jobs=-1,  # We use all the cores
        n_points=nCores,  # We allow nCores points to be evaluated at the same time
    )

    with tqdm(total=nCombinations) as pbar:

        def updateProgress(*args):
            pbar.update(min(nCores, bayes_search.n_iter - pbar.n))

        bayes_search.fit(data, data, callback=[updateProgress])

    # Best hyperparameter found
    print(f"Mejores hiperparámetros encontrados: {dict(bayes_search.best_params_)}")

    # Best puntuaction
    print(
        f"Mejor puntuación obtenida: {bayes_search.best_score_} usando {bayes_search.scorer_}."
    )

    # Best index
    print(
        f"Mejores hiperparámetros encontrados en la iteración número: {bayes_search.best_index_+1}"
    )
