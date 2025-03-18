import asyncio

from app.agent.manus import Manus
from app.agent.pentest import PenTestAgent
from app.logger import logger


async def main():
    print("Wähle den Agent-Typ:")
    print("1. Manus (Standard-Agent)")
    print("2. PenTest (Kali Linux Penetration Testing)")
    
    agent_choice = input("Wähle (1/2): ").strip()
    
    if agent_choice == "2":
        agent = PenTestAgent()
        print("\nDu hast den PenTest-Agent ausgewählt. Bitte gib deine Penetrationstest-Anfrage ein.")
        print("Beispiel: 'Führe einen umfassenden Scan der IP 192.168.1.1 durch'")
    else:
        agent = Manus()
        print("\nDu hast den Standard Manus-Agent ausgewählt. Bitte gib deine Anfrage ein.")
    
    try:
        prompt = input("\nEingabe: ")
        if not prompt.strip():
            logger.warning("Leere Eingabe.")
            return

        logger.warning("Verarbeite deine Anfrage...")
        await agent.run(prompt)
        logger.info("Anfrageverarbeitung abgeschlossen.")
    except KeyboardInterrupt:
        logger.warning("Vorgang abgebrochen.")


if __name__ == "__main__":
    asyncio.run(main())
