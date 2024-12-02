import matplotlib.pyplot as plt
import numpy as np
from typing import List, Dict
import cbrkit
import random
from valorador import Valorador
from tqdm import tqdm
import warnings
import visualization

# Ignorar todos los warnings específicos de spaCy
warnings.filterwarnings("ignore", message=r"\[W007\]")


def extraer_casos_a_resolver(
    base_de_casos: Dict[str, dict], cantidad: int
) -> List[dict]:
    """
    Extracts a random sample of cases from the base of cases.

    To extract all cases, set cantidad to 0.

    Args:
        - base_de_casos (Dict[str, dict]): The base of cases. The keys are
            the identifiers of the cases and the values are the cases.
        - cantidad (int): The number of cases to extract.

    Returns:
        - list: A list of cases.
    """
    if cantidad > len(base_de_casos):
        raise ValueError(
            f"La cantidad de casos a extraer ({cantidad}) no puede ser mayor que la cantidad de casos en la base de casos ({len(base_de_casos)})"
        )

    elif cantidad == 0:
        casos_a_resolver = list(base_de_casos.values())

    else:
        casos_a_resolver = []
        indices_aleatorios = sorted(random.sample(list(base_de_casos.keys()), cantidad))

        for i in indices_aleatorios:
            caso = base_de_casos.pop(i)
            casos_a_resolver.append(caso)

    return casos_a_resolver


if __name__ == "__main__":
    base_casos = cbrkit.loaders.json("./datos/base_casos.json")
    valorador = Valorador(base_casos, multiCore=True)
    casos_a_resolver = cbrkit.loaders.json("./datos/casos_a_resolver.json")
    casos_a_resolver = extraer_casos_a_resolver(casos_a_resolver, 100)

    contador_exitos = 0
    nStart = len(valorador.base_de_casos)
    realAV = []
    realScores = []
    predictedAV = []
    predictedScores = []

    for caso in tqdm(casos_a_resolver):
        caso_resuelto = valorador.ciclo_cbr(caso)
        if caso_resuelto["_meta"]["exito"]:
            contador_exitos += 1
        realAV.append(caso_resuelto["_meta"]["attack_vector_real"])
        realScores.append(caso_resuelto["_meta"]["score_real"])
        predictedAV.append(caso["_meta"]["attack_vector_predicho"])
        predictedScores.append(caso["_meta"]["score_predicho"])

    print(f"Número de casos exitosos: {contador_exitos} de {len(casos_a_resolver)}")
    print(
        f"Media de desviación de la score predicha: {sum(abs(np.array(realScores) - np.array(predictedScores))) / len(casos_a_resolver)}"
    )
    print(
        f"Se han añadido {len(valorador.base_de_casos)-nStart} casos a la base de casos."
    )

    visualization.showConfusionMatrix(realAV, predictedAV)
    visualization.plot_predictions(realScores, predictedScores)
    plt.show()
