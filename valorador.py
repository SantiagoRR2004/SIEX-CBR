from core import CBR, CBR_DEBUG

import cbrkit


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
            self.debug = CBR_DEBUG(self.prettyprint_caso)
        else:
            self.debug = None
        self.retriever = self.inicializar_retriever(num_casos_similares, taxonomia)

    def inicializar_retriever(self, num_casos_similares, taxonomia_cwe):
        cwe_similarity = cbrkit.sim.strings.taxonomy.load(taxonomia_cwe,
                                                          cbrkit.sim.strings.taxonomy.wu_palmer())
        assigner_similarity = cbrkit.sim.strings.levenshtein()
        keywords_similarity = cbrkit.sim.collections.jaccard()

        # añadir aquí otros modelos de similitud
        case_similarity = cbrkit.sim.attribute_value(
            attributes={
                "cwe": cwe_similarity,
                "assigner": assigner_similarity,
                "keywords": keywords_similarity,
            },
            aggregator=cbrkit.sim.aggregator(pooling="mean"), #se pueden añadir pesos (pooling_wieghts)
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

    def reutilizar(self, caso_a_resolver, casos_similares, similaridades):
        pass

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
        return "Caso " + str(caso.id) + ": " + caso.descripcion
    

if __name__ == "__main__":
    base_casos = cbrkit.loaders.json("./datos/base_casos.json")
    valorador = Valorador(base_casos)
    retriever = valorador.inicializar_retriever(100, "./datos/jerarquia_cwe_1000.yaml")