import cbrkit
import argparse
import pprint
import random
from valorador import Valorador

if __name__ == "__main__":
    base_casos = cbrkit.loaders.json("./datos/base_casos.json")
    valorador = Valorador(base_casos)
    casos_a_resolver = cbrkit.loaders.json("./datos/casos_a_resolver.json")

    contador_exitos = 0

    for caso in casos_a_resolver.values():
        caso_resuelto = valorador.ciclo_cbr(caso)
        if caso_resuelto["_meta"]["exito"]:
            contador_exitos += 1
        print("--- CASO RESUELTO ---")
        print(f"Score predicho: {caso["_meta"]["score_predicho"]}")
        print(f"Score real: {caso_resuelto['_meta']['score_real']}")
        print(f"Attack vector predicho: {caso['_meta']['attack_vector_predicho']}")
        print(f"Attack vector real: {caso_resuelto['_meta']['attack_vector_real']}")
        print("---------------------")

    print(f"Númeor de casos exitosos: {contador_exitos} de {len(casos_a_resolver)}")
