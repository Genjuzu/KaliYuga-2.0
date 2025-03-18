import asyncio
import time

from app.agent.manus import Manus
from app.agent.pentest import PenTestAgent
from app.flow.base import FlowType
from app.flow.flow_factory import FlowFactory
from app.logger import logger


async def run_flow():
    agents = {
        "manus": Manus(),
        "pentest": PenTestAgent(),
    }

    try:
        print("Wähle den Flow-Typ:")
        print("1. Planning Flow (Standard)")
        print("2. PenTest Flow (Kali Linux)")
        
        flow_choice = input("Wähle (1/2): ").strip()
        flow_type = FlowType.PLANNING
        
        if flow_choice == "2":
            flow_type = FlowType.PENTEST
            print("\nDu hast den PenTest Flow ausgewählt. Bitte gib deine Penetrationstest-Anfrage ein.")
            print("Beispiel: 'Führe einen umfassenden Scan der IP 192.168.1.1 durch'")
        else:
            print("\nDu hast den Standard Planning Flow ausgewählt. Bitte gib deine Anfrage ein.")

        prompt = input("\nEingabe: ")

        if prompt.strip().isspace() or not prompt:
            logger.warning("Leere Eingabe.")
            return

        print(f"\nVerwende Flow-Typ: {flow_type.value}")
        flow = FlowFactory.create_flow(
            flow_type=flow_type,
            agents=agents,
        )
        logger.warning("Verarbeite deine Anfrage...")

        try:
            start_time = time.time()
            result = await asyncio.wait_for(
                flow.execute(prompt),
                timeout=3600,  # 60 Minuten Timeout für die gesamte Ausführung
            )
            elapsed_time = time.time() - start_time
            logger.info(f"Anfrage in {elapsed_time:.2f} Sekunden verarbeitet")
            logger.info(result)
        except asyncio.TimeoutError:
            logger.error("Anfrage-Timeout nach 1 Stunde")
            logger.info(
                "Vorgang wegen Timeout abgebrochen. Bitte versuche eine einfachere Anfrage."
            )

    except KeyboardInterrupt:
        logger.info("Vorgang vom Benutzer abgebrochen.")
    except Exception as e:
        logger.error(f"Fehler: {str(e)}")


if __name__ == "__main__":
    asyncio.run(run_flow())
