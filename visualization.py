from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from typing import List
import numpy as np
import matplotlib.pyplot as plt
import os


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

    # Calculate the slope and intercept for the line of best fit
    slope, intercept = np.polyfit(correct, predicted, 1)
    regression_line = slope * diagonal + intercept

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

    # Diagonal line
    plt.plot(
        diagonal, diagonal, color="black", linestyle="--", label="Perfect Prediction"
    )

    # Line of best fit
    plt.plot(
        diagonal,
        regression_line,
        color="black",
        linestyle="-",
        label="Regression Line",
    )

    # Points
    plt.scatter(correct, predicted, color="blue", alpha=0.6, label="Predictions")

    plt.xlabel("Correct Values", fontsize=12)
    plt.ylabel("Predicted Values", fontsize=12)
    plt.title("Correct vs Predicted Values", fontsize=14)
    plt.legend()

    plt.xlim(min_val, max_val)
    plt.ylim(min_val, max_val)
    plt.grid(alpha=0.3)


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
