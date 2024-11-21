from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
from typing import List
import cbrkit
import argparse
import pprint
import random
from valorador import Valorador


def showConfusionMatrix(trueLabels: List[str], predictedLabels: List[str]) -> None:
    """
    Display a confusion matrix for the true and predicted labels.

    The labels are assumed to be one of the following:
        - NETWORK
        - ADJACENT NETWORK
        - LOCAL

    Args:
        - trueLabels (List[str]): List of true labels.
        - predictedLabels (List[str]): List of predicted labels.

    Returns:
        - None
    """
    # Compute confusion matrix
    cm = confusion_matrix(
        trueLabels, predictedLabels, labels=["NETWORK", "ADJACENT NETWORK", "LOCAL"]
    )

    # Display confusion matrix
    disp = ConfusionMatrixDisplay(
        confusion_matrix=cm, display_labels=["NETWORK", "ADJACENT NETWORK", "LOCAL"]
    )
    disp.plot(cmap="Blues")
    plt.show()


if __name__ == "__main__":
    base_casos = cbrkit.loaders.json("./datos/base_casos.json")
    valorador = Valorador(base_casos)
    casos_a_resolver = cbrkit.loaders.json("./datos/casos_a_resolver.json")

    contador_exitos = 0
    realAV = []
    predictedAV = []

    for caso in casos_a_resolver.values():
        caso_resuelto = valorador.ciclo_cbr(caso)
        if caso_resuelto["_meta"]["exito"]:
            contador_exitos += 1
        print("--- CASO RESUELTO ---")
        print(f"Score predicho: {caso_resuelto['_meta']['score_predicho']}")
        print(f"Score real: {caso_resuelto['_meta']['score_real']}")
        print(
            f"Attack vector predicho: {caso_resuelto['_meta']['attack_vector_predicho']}"
        )
        print(f"Attack vector real: {caso_resuelto['_meta']['attack_vector_real']}")
        print("---------------------")
        realAV.append(caso_resuelto["_meta"]["attack_vector_real"])
        predictedAV.append(caso["_meta"]["attack_vector_predicho"])

    print(f"Número de casos exitosos: {contador_exitos} de {len(casos_a_resolver)}")

    showConfusionMatrix(realAV, predictedAV)
