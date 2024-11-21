from abc import ABC, abstractmethod
from typing import List, Tuple


class CBR(ABC):
    def __init__(self, base_de_casos: dict, num_casos_similares: str = 1) -> None:
        """
        Stores the base of cases and the number of similar cases to retrieve.

        Args:
            - base_de_casos (dict): The base of cases.
            - num_casos_similares (int): The number of similar cases to retrieve.

        Returns:
            - None
        """
        self.base_de_casos = base_de_casos
        self.num_casos_similares = num_casos_similares

    def inicializar_caso(self, caso: dict, id: str = None) -> dict:
        """
        Initializes a case.

        Initializes a case by adding a _meta attribute to link metadata during the CBR cycle.

        Args:
            - caso (dict): The case to initialize.
            - id (str): The case identifier.

        Returns:
            - dict: The initialized case.
        """
        # crear un atributo _meta para vincular metadatos durante el ciclo CBR
        caso["_meta"] = {}

        if id is not None:
            caso["_meta"]["id"] = id
        else:
            # comprobar si el caso tiene un identificador interno, tomar nota del mismo
            if "id" in caso:
                caso["_meta"]["id"] = caso["id"]
            if "uuid" in caso:
                caso["_meta"]["id"] = caso["uuid"]

        return caso

    @abstractmethod
    def recuperar(self, caso_a_resolver: dict) -> Tuple[List[dict], List[float]]:
        """
        Retrieves similar cases from the case base.

        This method should be implemented by subclasses.

        Args:
            - caso_a_resolver (dict): The case to resolve.

        Returns:
            - tuple: A tuple containing 2 lists:
                - List[dict]: The similar cases.
                - List[float]: The similarity scores.
        """
        pass

    @abstractmethod
    def reutilizar(
        self,
        caso_a_resolver: dict,
        casos_similares: List[dict],
        similaridades: List[float],
    ) -> dict:
        """
        Reuses similar cases to resolve the current case.

        This method should be implemented by subclasses.

        Args:
            - caso_a_resolver (dict): The case to resolve.
            - casos_similares (List[dict]): The similar cases.
            - similaridades (List[float]): The similarity scores.

        Returns:
            - dict: The resolved case.
        """
        pass

    @abstractmethod
    def revisar(
        self,
        caso_resuelto: dict,
        caso_a_resolver: dict = None,
        casos_similares: List[dict] = None,
        similaridades: List[float] = None,
    ) -> dict:
        """
        Reviews the resolved case.

        This method should be implemented by subclasses.

        Args:
            - caso_resuelto (dict): The resolved case.
            - caso_a_resolver (dict): The case to resolve.
            - casos_similares (List[dict]): The similar cases.
            - similaridades (List[float]): The similarity scores.

        Returns:
            - dict: The reviewed case.
        """
        pass

    @abstractmethod
    def retener(
        self,
        caso_revisado: dict,
        caso_a_resolver: dict = None,
        casos_similares: List[dict] = None,
        similaridades: List[float] = None,
    ) -> None:
        """
        Retains the reviewed case if deemed necessary.

        This method should be implemented by subclasses.

        Args:
            - caso_revisado (dict): The reviewed case.
            - caso_a_resolver (dict): The case to resolve.
            - casos_similares (List[dict]): The similar cases.
            - similaridades (List[float]): The similarity scores.

        Returns:
            - None
        """
        pass

    def ciclo_cbr(self, caso_a_resolver: dict, id_caso: str = None) -> dict:
        """
        Executes a CBR cycle to resolve a case.

        First, initializes the case to resolve. Then, retrieves similar cases from the case base.
        Next, reuses the similar cases to resolve the current case. After that, reviews the resolved
        case. Finally, retains the reviewed case if deemed necessary.

        Args:
            - caso_a_resolver (dict): The case to resolve.
            - id_caso (str): The case identifier.

        Returns:
            - dict: The finished case.
        """
        caso_a_resolver = self.inicializar_caso(caso_a_resolver, id=id_caso)
        (casos_similares, similaridades) = self.recuperar(caso_a_resolver)
        caso_resuelto = self.reutilizar(caso_a_resolver, casos_similares, similaridades)
        caso_revisado = self.revisar(
            caso_resuelto, caso_a_resolver, casos_similares, similaridades
        )
        self.retener(caso_revisado, caso_a_resolver, casos_similares, similaridades)
        return caso_revisado


class CBR_DEBUG:
    def __init__(self, prettyprint_caso):
        self.prettyprint_caso = prettyprint_caso

    def debug_mensaje(self, etiqueta, mensaje=""):
        print("[{}] {}".format(etiqueta, mensaje))

    def debug_recuperar(self, caso, similares, scores):
        self.debug_mensaje(
            "DEBUG.recuperar", mensaje="CASO A RESOLVER: " + self.prettyprint_caso(caso)
        )
        self.debug_mensaje(
            "DEBUG.recuperar",
            mensaje="CASOS SIMILARES (total: {}, similaridad max.:{})".format(
                len(similares), scores[0]
            ),
        )

        count = 1
        for c, score in zip(similares, scores):
            self.debug_mensaje(
                "DEBUG.recuperar",
                mensaje="- [{}] {}  (Similaridad: {})".format(
                    count, self.prettyprint_caso(c), score
                ),
            )
            count = count + 1
        self.debug_mensaje("DEBUG.recuperar")

    def debug_reutilizar(self, caso_resuelto):
        self.debug_mensaje(
            "DEBUG.reutilizar",
            mensaje="CASO RESUELTO: " + self.prettyprint_caso(caso_resuelto),
        )
        self.debug_mensaje("DEBUG.retutilzar")

    def debug_revisar(self, caso_revisado, es_exito=None, es_corregido=None):
        self.debug_mensaje(
            "DEBUG.revisar",
            mensaje="CASO REVISADO: " + self.prettyprint_caso(caso_revisado),
        )
        if es_exito is not None:
            self.debug_mensaje("DEBUG.revisar", mensaje="- exito: {}".format(es_exito))
        if es_corregido is not None:
            self.debug_mensaje(
                "DEBUG.revisar", mensaje="- corregido: {}".format(es_corregido)
            )
        self.debug_mensaje("DEBUG.revisar")

    def debug_retener(self, caso_retenido, es_retenido=None):
        self.debug_mensaje(
            "DEBUG.retener",
            mensaje="CASO RETENIDO: " + self.prettyprint_caso(caso_retenido),
        )
        if es_retenido is not None:
            if es_retenido and ("id" in caso_retenido):
                self.debug_mensaje(
                    "DEBUG.retener",
                    "- retenido: {} con id manual: {}".format(
                        es_retenido, caso_retenido["id"]
                    ),
                )
            else:
                self.debug_mensaje(
                    "DEBUG.retener", "- retenido: {}".format(es_retenido)
                )
        self.debug_mensaje("DEBUG_retener")
