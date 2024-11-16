from core import CBR, CBR_DEBUG

import cbrkit


class Valorador(CBR):
    def __init__(
        self,
        base_de_casos,
        num_casos_similares=100,
        taxonomia="./datos/taxonomia.json",
        debug=False,
    ):
        super().__init__(base_de_casos, num_casos_similares)
        if debug:
            self.debug = CBR_DEBUG(self.prettyprint_caso)
        else:
            self.debug = None
        self.retriever = self.inicializar_retriever(num_casos_similares, taxonomia)

    def inicializar_retriever(self, num_casos_similares, taxonomia):
        model_similarity = cbrkit.sim.attribute_value(
            attributes={
                "assigner": cbrkit.sim.strings.jaro()
                # añadir aquí otros atributos
            },
            aggregator=cbrkit.sim.aggregator(pooling="mean"),
        )

        # añadir aquí otros modelos de similitud
        case_similarity = cbrkit.sim.attribute_value(
            attributes={
                "model": model_similarity,
            },
            aggregator=cbrkit.sim.aggregator(pooling="mean"),
        )
        retriever = cbrkit.retrieval.build(case_similarity, limit=num_casos_similares)
        return retriever

    def similaridad(self, caso_a, caso_b):
        return self.retriever.similaridad(caso_a, caso_b)

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

    """
    def evaluar(self, caso_a_evaluar):
        similares, scores = self.recuperar(caso_a_evaluar)

        if len(similares) == 0:
            return None # No hay casos similares
        
        elif len(similares) == 1:
            return similares[0] # Solo hay un caso similar
        
        else:
            if self.similaridad_max is not None:
                scores = [score for score in scores if score <= self.similaridad_max]
            return similares[scores.index(max(scores))] # Retorna el caso similar con mayor similitud
    """

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
