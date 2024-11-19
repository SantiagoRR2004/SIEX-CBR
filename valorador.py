from core import CBR, CBR_DEBUG
from typing import List
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
        base_de_casos,
        num_casos_similares=100,
        taxonomia="./datos/jerarquia_cwe_1000.yaml",
        debug=False,
    ):
        super().__init__(base_de_casos, num_casos_similares)
        if debug:
            self.DEBUG = CBR_DEBUG(self.prettyprint_caso)
        else:
            self.DEBUG = None
        self.retriever = self.inicializar_retriever(num_casos_similares, taxonomia)

    def inicializar_retriever(self, num_casos_similares, taxonomia_cwe):
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
            ),  # se pueden añadir pesos (pooling_wieghts)
        )

        # crear un objeto de recuperación
        retriever = cbrkit.retrieval.build(case_similarity, limit=num_casos_similares)
        return retriever

    def inicializar_caso(self, caso, id=None):
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

        return caso

    def recuperar(self, caso_a_resolver):
        result = cbrkit.retrieval.apply(
            self.base_de_casos, caso_a_resolver, self.retriever
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
        caso_resuelto,
        caso_a_resolver=None,
        casos_similares=None,
        similaridades=None,
    ):
        pass

    def retener(
        self,
        caso_revisado,
        caso_a_resolver=None,
        casos_similares=None,
        similaridades=None,
    ):
        pass

    def prettyprint_caso(self, caso):
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
