from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import numpy as np
from typing import List
import cbrkit
import argparse
import pprint
import random
from valorador import Valorador


def extraer_casos_a_resolver(base_de_casos, cantidad):
    """
    Extracts a random sample of cases from the base of cases.

    Args:
        - base_de_casos (dict): The base of cases.
        - cantidad (int): The number of cases to extract.

    Returns:
        - list: A list of cases.
    """
    casos_a_resolver = []
    indices_aleatorios = sorted(random.sample(list(base_de_casos.keys()), cantidad))

    for i in indices_aleatorios:
        caso = base_de_casos.pop(i)
        casos_a_resolver.append(caso)
    return casos_a_resolver


def showConfusionMatrix(trueLabels: List[str], predictedLabels: List[str]) -> None:
    """
    Display a confusion matrix for the true and predicted labels.

    The labels are assumed to be one of the following:
        - NETWORK
        - ADJACENT_NETWORK
        - LOCAL

    Args:
        - trueLabels (List[str]): List of true labels.
        - predictedLabels (List[str]): List of predicted labels.

    Returns:
        - None
    """
    # Compute confusion matrix
    cm = confusion_matrix(
        trueLabels, predictedLabels, labels=["NETWORK", "ADJACENT_NETWORK", "LOCAL"]
    )

    # Display confusion matrix
    disp = ConfusionMatrixDisplay(
        confusion_matrix=cm, display_labels=["NETWORK", "ADJACENT_NETWORK", "LOCAL"]
    )
    disp.plot(cmap="Blues")


def plot_predictions(correct: List[float], predicted: List[float]) -> None:
    """
    Plots a scatter plot of correct vs. predicted values and a diagonal line.

    Args:
        - correct (List[float]): List of correct values.
        - predicted (List[float]): List of predicted values.

    Returns:
        - None
    """
    # Ensure inputs are numpy arrays for compatibility
    correct = np.array(correct)
    predicted = np.array(predicted)

    # The range for the plot
    min_val = 0
    max_val = 10

    # Create a diagonal line
    diagonal = np.linspace(min_val, max_val, 500)

    # Plotting
    plt.figure(figsize=(8, 8))

    # Now we color the background based on the ratings

    # Critical Severity
    plt.axvspan(9, 10, color="red")
    plt.axhspan(9, 10, color="red")

    # High Severity
    plt.axvspan(7, 9, color="orange")
    plt.axhspan(7, 9, color="orange")

    # Medium Severity
    plt.axvspan(4, 7, color="yellow")
    plt.axhspan(4, 7, color="yellow")

    # Low Severity
    plt.axvspan(0, 4, color="green")
    plt.axhspan(0, 4, color="green")

    plt.plot(
        diagonal, diagonal, color="black", linestyle="--", label="Perfect Prediction"
    )  # Diagonal line

    plt.scatter(
        correct, predicted, color="blue", alpha=0.6, label="Predictions"
    )  # Points

    plt.xlabel("Correct Values", fontsize=12)
    plt.ylabel("Predicted Values", fontsize=12)
    plt.title("Correct vs Predicted Values", fontsize=14)
    plt.legend()

    plt.xlim(min_val, max_val)
    plt.ylim(min_val, max_val)
    plt.grid(alpha=0.3)


if __name__ == "__main__":
    base_casos = cbrkit.loaders.json("./datos/base_casos.json")
    valorador = Valorador(base_casos)
    casos_a_resolver = cbrkit.loaders.json("./datos/casos_a_resolver.json")
    casos_a_resolver = extraer_casos_a_resolver(casos_a_resolver, 100)

    contador_exitos = 0
    nStart = len(valorador.base_de_casos)
    realAV = []
    realScores = []
    predictedAV = []
    predictedScores = []

    for caso in casos_a_resolver:
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

    showConfusionMatrix(realAV, predictedAV)
    plot_predictions(realScores, predictedScores)
    plt.show()
