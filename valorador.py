from core import CBR, CBR_DEBUG
from typing import List, Tuple
from statistics import mode
import os
import cbrkit


def getTerminalSize() -> tuple:
    """
    Get the size of the terminal window in characters.

    Args:
        - None

    Returns:
        - tuple: (width, height) of the terminal window in characters
    """
    try:
        terminalSize = os.get_terminal_size()
        terminalWidth = terminalSize.columns
        terminalHeight = terminalSize.lines
    except OSError:
        # Default dimensions if terminal size cannot be determined
        terminalWidth = 80
        terminalHeight = 24

    return terminalWidth, terminalHeight


def centerText(text: str, *, fillchar: str = "*", nFill: int = 2) -> str:
    """
    Center text in the terminal window. It adds the
    number of fill characters specified by nFill to
    the left and right of the text.

    Args:
        - text (str): Text to center
        - fillchar (str): Character to use for filling
        - nFill (int): Number of fill characters to use

    Returns:
        - str: Text centered in the terminal window
    """
    term = getTerminalSize()
    return fillchar * nFill + text.center(term[0] - 2 * nFill) + fillchar * nFill + "\n"


class Valorador(CBR):
    def __init__(
        self,
        base_de_casos: List[dict],
        *,
        umbralScore: int = 1,
        num_casos_similares: int = 100,
        taxonomia: str = "./datos/jerarquia_cwe_1000.yaml",
        debug: bool = False,
    ) -> None:
        """
        Initializes the Valorador object.

        Args:
            - base_de_casos (List[dict]): List of cases to use as the base
            - umbralScore (int): Threshold to consider the score correct
            - num_casos_similares (int): Number of similar cases to retrieve
            - taxonomia (str): Path to the CWE taxonomy file
            - debug (bool): Flag to enable debugging

        Returns:
            - None
        """
        super().__init__(base_de_casos, num_casos_similares)
        if debug:
            self.DEBUG = CBR_DEBUG(self.prettyprint_caso)
        else:
            self.DEBUG = None
        self.retriever = self.inicializar_retriever(num_casos_similares, taxonomia)
        self.umbralScore = umbralScore

    def inicializar_retriever(
        self, num_casos_similares: int, taxonomia_cwe: str
    ) -> cbrkit.retrieval.RetrieverFunc:
        """
        Initializes the retriever function to retrieve similar cases.

        **Explain each type of similarity**

        Args:
            - num_casos_similares (int): Number of similar cases to retrieve
            - taxonomia_cwe (str): Path to the CWE taxonomy file

        Returns:
            - cbrkit.retrieval.RetrieverFunc: Retriever function to retrieve similar cases
        """
        cwe_similarity = cbrkit.sim.strings.taxonomy.load(
            taxonomia_cwe, cbrkit.sim.strings.taxonomy.wu_palmer()
        )
        assigner_similarity = cbrkit.sim.strings.levenshtein()
        keywords_similarity = cbrkit.sim.collections.jaccard()
        affected_products_similarity = cbrkit.sim.collections.isolated_mapping(
            cbrkit.sim.strings.jaro()
        )

        # añadir aquí otros modelos de similitud
        case_similarity = cbrkit.sim.attribute_value(
            attributes={
                "cwe": cwe_similarity,
                "assigner": assigner_similarity,
                "affected_products": affected_products_similarity,
                "keywords": keywords_similarity,
            },
            aggregator=cbrkit.sim.aggregator(
                pooling="mean"
            ),  # se pueden añadir pesos (pooling_weights)
        )

        # crear un objeto de recuperación
        retriever = cbrkit.retrieval.build(case_similarity, limit=num_casos_similares)
        return retriever

    def inicializar_caso(self, caso: dict, id: str = None) -> dict:
        """
        Initializes a case.

        Initializes a case by adding a _meta attribute to link metadata during the CBR cycle.
        It adds the following attributes to the _meta attribute:
            - score_real: Real score of the case
            - score_predicho: Predicted score of the case
            - score_exito: Flag to indicate if the predicted score is correct
            - score_corregido: Flag to indicate if the predicted score is used
            - attack_vector_real: Real attack vector of the case
            - attack_vector_predicho: Predicted attack vector of the case
            - attack_vector_exito: Flag to indicate if the predicted attack vector is correct
            - attack_vector_corregido: Flag to indicate if the predicted attack vector is used
            - exito: Flag to indicate if the case is successful

        Args:
            - caso (dict): The case to initialize.
            - id (str): The case identifier.

        Returns:
            - dict: The initialized case.
        """
        caso = super().inicializar_caso(caso, id)

        if "score" in caso["metric"]:
            caso["_meta"]["score_real"] = caso["metric"]["score"]
        else:
            caso["_meta"]["score_real"] = 0.0

        caso["_meta"]["score_predicho"] = 0.0
        caso["_meta"]["score_exito"] = False
        caso["_meta"]["score_corregido"] = False

        if "attackVector" in caso["metric"]:
            caso["_meta"]["attack_vector_real"] = caso["metric"]["attackVector"]
        else:
            caso["_meta"]["attack_vector_real"] = None

        caso["_meta"]["attack_vector_predicho"] = None
        caso["_meta"]["attack_vector_exito"] = False
        caso["_meta"]["attack_vector_corregido"] = False

        caso["_meta"]["exito"] = False

        return caso

    def recuperar(self, caso_a_resolver: dict) -> Tuple[List[dict], List[float]]:
        """
        Retrieves similar cases from the case base.

        Args:
            - caso_a_resolver (dict): Case to solve

        Returns:
            - tuple: A tuple containing 2 lists:
                - List[dict]: The similar cases.
                - List[float]: The similarity scores.
        """
        result = cbrkit.retrieval.apply(
            self.base_de_casos, caso_a_resolver, self.retriever, processes=0
        )
        casos_similares = []
        similaridades = []
        for i in result.ranking:
            casos_similares.append(self.base_de_casos[i])
            similaridades.append(result.similarities[i].value)

        # DEBUG
        if self.DEBUG:
            self.DEBUG.debug_recuperar(caso_a_resolver, casos_similares, similaridades)

        return (casos_similares, similaridades)

    def reutilizar(
        self,
        caso_a_resolver: dict,
        casos_similares: List[dict],
        similaridades: List[float],
    ) -> dict:
        """
        Reuse the most similar cases to the case to predict
        the score and attack vector of the case to solve.

        casos_similares and similaridades must be in order
        and be the same length.

        Args:
            - caso_a_resolver (dict): Case to solve
            - casos_similares (list[dict]): List of similar cases
            - similaridades (list[float]): List of similarities between the case to solve and the similar cases

        Returns:
            - dict: Case solved with the predicted score and attack vector
        """
        # First we predict the score
        weightedSum = sum(
            d["metric"]["score"] * w for d, w in zip(casos_similares, similaridades)
        )
        weightTotal = sum(similaridades)

        caso_a_resolver["_meta"]["score_predicho"] = (
            weightedSum / weightTotal if weightTotal else 0
        )

        # Then we predict the attack vector
        attackVectors = [d["metric"]["attackVector"] for d in casos_similares]
        caso_a_resolver["_meta"]["attack_vector_predicho"] = mode(attackVectors)

        return caso_a_resolver

    def revisar(
        self,
        caso_resuelto: dict,
        caso_a_resolver: dict = None,
        casos_similares: List[dict] = None,
        similaridades: List[float] = None,
    ) -> dict:
        """
        Revises the case. It checks if the predicted score and attack vector.

        It considers the score correct if it is within the threshold
        and if it is in the same CVSS 3.0 range.
        https://www.hackercoolmagazine.com/wp-content/uploads/2023/09/CVSS_vulnerability_scoring_1.jpg

        If it is successful it puts the predicted score as the real score.
        If it is not successful it puts the real score as the real score.

        It considers the attack vector correct if it is the same as the predicted one.

        If it is successful it puts the predicted attack vector as the real attack vector.
        If it is not successful it puts the real attack vector as the real attack vector.

        For the entire case to be succesful it needs either the score or the attack vector to be correct.
        If neither is correct the case is not successful.

        Args:
            - caso_resuelto (dict): Case solved with the predicted score and attack vector
            - caso_a_resolver (dict): Case to solve
            - casos_similares (list[dict]): List of similar cases
            - similaridades (list[float]): List of similarities between the case to solve and the similar cases

        Returns:
            - dict: Case solved with the corrected score and attack vector
        """
        # First we check the score
        realScore = caso_resuelto["_meta"]["score_real"]
        predictedScore = caso_resuelto["_meta"]["score_predicho"]

        caso_resuelto["_meta"]["score_exito"] = True

        # It needs to be within the threshold
        if abs(realScore - predictedScore) > self.umbralScore:
            caso_resuelto["_meta"]["score_exito"] = False

        # It also needs to be in the same CVSS 3.0 range

        # Low severity
        if realScore >= 0.1 and realScore < 3.9:
            if predictedScore < 0.1 or predictedScore >= 3.9:
                caso_resuelto["_meta"]["score_exito"] = False

        # Medium severity
        elif realScore >= 4.0 and realScore < 6.9:
            if predictedScore < 4.0 or predictedScore >= 6.9:
                caso_resuelto["_meta"]["score_exito"] = False

        # High severity
        elif realScore >= 7.0 and realScore < 8.9:
            if predictedScore < 7.0 or predictedScore >= 8.9:
                caso_resuelto["_meta"]["score_exito"] = False

        # Critical severity
        elif realScore >= 9.0 and realScore <= 10.0:
            if predictedScore < 9.0 or predictedScore > 10.0:
                caso_resuelto["_meta"]["score_exito"] = False

        # If it is successful we put the predicted score
        if caso_resuelto["_meta"]["score_exito"]:
            caso_resuelto["_meta"]["score_corregido"] = False
            caso_resuelto["metric"]["score"] = caso_resuelto["_meta"]["score_predicho"]
        # If it is not successful we put the real score
        else:
            caso_resuelto["_meta"]["score_corregido"] = True
            caso_resuelto["metric"]["score"] = caso_resuelto["_meta"]["score_real"]

        # Then we check the attack vector
        if (
            caso_resuelto["_meta"]["attack_vector_real"]
            != caso_resuelto["_meta"]["attack_vector_predicho"]
        ):
            caso_resuelto["_meta"]["attack_vector_exito"] = False
        else:
            caso_resuelto["_meta"]["attack_vector_exito"] = True

        # If it is successful we put the predicted attack vector
        if caso_resuelto["_meta"]["attack_vector_exito"]:
            caso_resuelto["_meta"]["attack_vector_corregido"] = False
            caso_resuelto["metric"]["attackVector"] = caso_resuelto["_meta"][
                "attack_vector_predicho"
            ]
        # If it is not successful we put the real attack vector
        else:
            caso_resuelto["_meta"]["attack_vector_corregido"] = True
            caso_resuelto["metric"]["attackVector"] = caso_resuelto["_meta"][
                "attack_vector_real"
            ]

        # Now we check the general success
        if (
            caso_resuelto["_meta"]["score_exito"]
            or caso_resuelto["_meta"]["attack_vector_exito"]
        ):
            caso_resuelto["_meta"]["exito"] = True
        else:
            caso_resuelto["_meta"]["exito"] = False

        return caso_resuelto

    def retener(
        self,
        caso_revisado: dict,
        caso_a_resolver: dict = None,
        casos_similares: List[dict] = None,
        similaridades: List[float] = None,
    ) -> None:
        """
        Retains the case if it has been corrected
        or if the attack vector has been successful.

        Args:
            - caso_revisado (dict): The reviewed case.
            - caso_a_resolver (dict): The case to resolve.
            - casos_similares (List[dict]): The similar cases.
            - similaridades (List[float]): The similarity scores.

        Returns:
            - None
        """
        es_retenido = False

        # retener casos que se han corregido
        if (
            not caso_revisado["_meta"]["score_exito"]
            or not caso_revisado["_meta"]["attack_vector_exito"]
        ):
            es_retenido = True
        elif (
            caso_revisado["_meta"]["exito"]
            and caso_revisado["_meta"]["attack_vector_exito"]
        ):
            es_retenido = True

        if es_retenido:
            print(f"Caso {caso_revisado['_meta']['id']} retenido")
            self.base_de_casos[len(self.base_de_casos) - 1] = caso_revisado

    def prettyprint_caso(self, caso: dict) -> str:
        """
        Generates the string to pretty print a case.
        It requires the case to have the following attributes:
            - id
            - title
            - assigner
            - affected_products

        Args:
            - caso (dict): Case to pretty print

        Returns:
            - str: Pretty printed case
        """
        term = getTerminalSize()
        toret = "*" * term[0] + "\n"
        toret += " Vulnerability Report ".center(term[0], "*") + "\n"
        toret += centerText("")
        toret += centerText(caso["id"])
        toret += centerText(caso["title"])
        toret += centerText("")
        toret += centerText(f"Assigned to: {caso['assigner']}")
        toret += centerText("")
        toret += centerText("Affected products:")
        toret += centerText("")
        if len(caso["affected_products"]) > 1:
            toret += "".join(
                [
                    centerText(x)
                    for x in self.prettyprintAffected(caso["affected_products"]).split(
                        "\n"
                    )
                ]
            )
        else:
            toret += centerText(caso["affected_products"][0])
        toret += centerText("")

        toret += "*" * term[0] + "\n" + "*" * term[0] + "\n"
        return toret

    def prettyprintAffected(self, affected: list) -> str:
        """
        Pretty print a list of affected products.
        It returns the string with the products listed
        with a bullet point in front of them, aligned
        to the right and with an empty line between them.

        Args:
            - affected (list): List of affected products

        Returns:
            - str: Pretty printed list of affected products
        """
        maxLen = max([len(x) for x in affected])

        toret = "\n\n".join(["- " + x.ljust(maxLen) for x in affected])

        return toret


if __name__ == "__main__":
    base_casos = cbrkit.loaders.json("./datos/base_casos.json")
    valorador = Valorador(base_casos)
    # retriever = valorador.inicializar_retriever(100, "./datos/jerarquia_cwe_1000.yaml")
    aResolver = cbrkit.loaders.json("./datos/casos_a_resolver.json")

    caso = valorador.inicializar_caso(aResolver[58])

    # print(aResolver[58])

    # print(valorador.prettyprint_caso(aResolver[58]))

    closest = valorador.recuperar(caso)

    valorador.reutilizar(caso, closest[0], closest[1])

    print(caso["_meta"]["score_predicho"])
    print(caso["_meta"]["score_real"])
    print(caso["_meta"]["attack_vector_predicho"])
    print(caso["_meta"]["attack_vector_real"])
