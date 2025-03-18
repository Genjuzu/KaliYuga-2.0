#!/usr/bin/env python3
# KaliYuga Knowledge Base Tool
# Speichert und verwaltet Erkenntnisse, Phasen und Aufgaben für den KaliYuga-Agenten

import json
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, ClassVar

from app.tool.base import BaseTool
from app.logger import logger
from pydantic import Field


class KaliKnowledgeBase(BaseTool):
    """
    Tool zum Speichern, Abrufen und Verwalten von Erkenntnissen während Penetrationstests.
    
    Ermöglicht dem KaliYuga-Agenten, ein "Gedächtnis" zu haben und strukturierte Informationen
    über Ziele, Schwachstellen und Erkenntnisse zu speichern und für spätere Schritte zu verwenden.
    
    Das Tool unterstützt auch die Verwaltung der aktuellen Pentesting-Phase und Aufgaben.
    """

    # Penetrationstest-Phasen mit Typannotation als ClassVar
    PHASES: ClassVar[List[str]] = [
        "reconnaissance",
        "vulnerability_assessment",
        "exploitation",
        "post_exploitation",
        "reporting"
    ]
    
    # Spezifische Aufgaben mit Typannotation als ClassVar
    TASKS: ClassVar[List[str]] = [
        "network_scan",
        "web_application",
        "wifi_testing",
        "password_attacks"
    ]
    
    # Pydantic-Felder für die Klasse
    storage_dir: str = Field(default=None, description="Speicherpfad für persistente Daten")
    current_phase: Optional[str] = Field(default=None, description="Aktuelle Phase des Penetrationstests")
    current_task: Optional[str] = Field(default=None, description="Aktuelle Aufgabe")
    knowledge: Dict[str, List[Dict]] = Field(default_factory=dict, description="Wissensdatenbank mit verschiedenen Kategorien")
    activity_log: List[Dict] = Field(default_factory=list, description="Aktivitätsprotokoll")
    
    def __init__(self, storage_dir: str = None, **kwargs):
        """Initialisiert die Wissensdatenbank mit einem optionalen Speicherpfad."""
        # Name und Beschreibung direkt setzen
        tool_name = "knowledge_base"
        tool_description = "Speichert Erkenntnisse während des Penetrationstests und verwaltet die aktuelle Phase und Aufgabe"
        
        # Parameter für das Tool definieren
        tool_parameters = {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Die auszuführende Aktion (add_entry, get_entries, search_entries, set_phase, get_phase, set_task, get_task, extract_findings, get_context_for_prompt, generate_report)",
                    "enum": ["add_entry", "get_entries", "search_entries", "set_phase", "get_phase", "set_task", "get_task", "extract_findings", "get_context_for_prompt", "generate_report"]
                },
                "category": {
                    "type": "string",
                    "description": "Die Kategorie für die Aktion (hosts, ports, services, vulnerabilities, credentials, files)"
                },
                "data": {
                    "type": "object",
                    "description": "Die zu speichernden Daten für add_entry"
                },
                "limit": {
                    "type": "integer",
                    "description": "Optionale Begrenzung der Ergebnisse für get_entries"
                },
                "query": {
                    "type": "string",
                    "description": "Suchbegriff für search_entries"
                },
                "phase": {
                    "type": "string",
                    "description": "Die zu setzende Phase für set_phase"
                },
                "task": {
                    "type": "string",
                    "description": "Die zu setzende Aufgabe für set_task"
                },
                "content": {
                    "type": "string",
                    "description": "Der zu analysierende Text für extract_findings"
                }
            },
            "required": ["action"]
        }
        
        # BaseTool-Konstruktor aufrufen
        super().__init__(
            name=tool_name,
            description=tool_description,
            parameters=tool_parameters
        )
        
        # Speicherpfad für persistente Daten
        self.storage_dir = storage_dir or os.path.join(os.getcwd(), "logs/knowledge")
        os.makedirs(self.storage_dir, exist_ok=True)
        
        # Wissensdatenbank mit verschiedenen Kategorien initialisieren
        self.knowledge = {
            "hosts": [],       # Gefundene Hosts/IPs
            "ports": [],       # Offene Ports
            "services": [],    # Erkannte Dienste
            "vulnerabilities": [],  # Gefundene Schwachstellen
            "credentials": [], # Gefundene Zugangsdaten
            "files": []        # Interessante Dateien
        }
        
        logger.info("KaliKnowledgeBase initialisiert")

    def add_entry(self, category: str, data: dict) -> str:
        """
        Fügt einen Eintrag zur angegebenen Kategorie hinzu.
        
        Args:
            category: Die Kategorie für den Eintrag (hosts, ports, services, vulnerabilities, etc.)
            data: Die zu speichernden Daten als Dictionary
            
        Returns:
            Eine Bestätigungsnachricht
        """
        if category not in self.knowledge:
            self.knowledge[category] = []
        
        # Zeitstempel hinzufügen
        data["timestamp"] = datetime.now().isoformat()
        
        # Eintrag hinzufügen
        self.knowledge[category].append(data)
        
        # Aktivität protokollieren
        self.activity_log.append({
            "action": "add_entry",
            "category": category,
            "data": data,
            "timestamp": datetime.now().isoformat()
        })
        
        # Daten speichern
        self._save_knowledge()
        
        return f"Eintrag in Kategorie '{category}' hinzugefügt"

    def get_entries(self, category: str, limit: int = None) -> List[Dict]:
        """
        Ruft Einträge aus der angegebenen Kategorie ab.
        
        Args:
            category: Die Kategorie, aus der abgerufen werden soll
            limit: Optionale Beschränkung der Anzahl zurückgegebener Einträge
            
        Returns:
            Eine Liste der Einträge
        """
        if category not in self.knowledge:
            return []
        
        entries = self.knowledge[category]
        if limit:
            return entries[-limit:]
        return entries

    def search_entries(self, category: str, query: str) -> List[Dict]:
        """
        Durchsucht Einträge in der angegebenen Kategorie nach einem Suchbegriff.
        
        Args:
            category: Die zu durchsuchende Kategorie
            query: Der Suchbegriff
            
        Returns:
            Eine Liste der passenden Einträge
        """
        if category not in self.knowledge:
            return []
        
        # Einfache Suche
        results = []
        for entry in self.knowledge[category]:
            for value in entry.values():
                if isinstance(value, str) and query.lower() in value.lower():
                    results.append(entry)
                    break
        
        return results

    def get_all_knowledge(self) -> Dict[str, List[Dict]]:
        """
        Ruft die gesamte Wissensdatenbank ab.
        
        Returns:
            Die gesamte Wissensdatenbank als Dictionary
        """
        return self.knowledge

    def set_phase(self, phase: str) -> str:
        """
        Setzt die aktuelle Phase des Penetrationstests.
        
        Args:
            phase: Die zu setzende Phase (reconnaissance, vulnerability_assessment, etc.)
            
        Returns:
            Eine Bestätigungsnachricht
        """
        if phase not in self.PHASES:
            valid_phases = ", ".join(self.PHASES)
            return f"Ungültige Phase. Gültige Phasen sind: {valid_phases}"
        
        self.current_phase = phase
        
        # Aktivität protokollieren
        self.activity_log.append({
            "action": "set_phase",
            "phase": phase,
            "timestamp": datetime.now().isoformat()
        })
        
        return f"Phase auf '{phase}' gesetzt"

    def get_phase(self) -> Optional[str]:
        """
        Ruft die aktuelle Phase des Penetrationstests ab.
        
        Returns:
            Die aktuelle Phase oder None, wenn keine gesetzt ist
        """
        return self.current_phase

    def set_task(self, task: str) -> str:
        """
        Setzt die aktuelle Aufgabe.
        
        Args:
            task: Die zu setzende Aufgabe (network_scan, web_application, etc.)
            
        Returns:
            Eine Bestätigungsnachricht
        """
        if task not in self.TASKS:
            valid_tasks = ", ".join(self.TASKS)
            return f"Ungültige Aufgabe. Gültige Aufgaben sind: {valid_tasks}"
        
        self.current_task = task
        
        # Aktivität protokollieren
        self.activity_log.append({
            "action": "set_task",
            "task": task,
            "timestamp": datetime.now().isoformat()
        })
        
        return f"Aufgabe auf '{task}' gesetzt"

    def get_task(self) -> Optional[str]:
        """
        Ruft die aktuelle Aufgabe ab.
        
        Returns:
            Die aktuelle Aufgabe oder None, wenn keine gesetzt ist
        """
        return self.current_task

    def extract_findings(self, content: str) -> Dict[str, List[str]]:
        """
        Extrahiert automatisch Erkenntnisse aus einer Textantwort.
        
        Args:
            content: Der zu analysierende Text
            
        Returns:
            Ein Dictionary mit extrahierten Erkenntnissen nach Kategorien
        """
        findings = {
            "hosts": [],
            "ports": [],
            "services": [],
            "vulnerabilities": []
        }
        
        # IP-Adressen extrahieren
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.findall(ip_pattern, content)
        for ip in ip_matches:
            findings["hosts"].append({
                "ip": ip,
                "source": "text_extraction",
                "confidence": "medium"
            })
        
        # Ports extrahieren
        port_pattern = r'Port (\d+).*?(offen|open|geschlossen|closed)'
        port_matches = re.findall(port_pattern, content, re.IGNORECASE)
        for port, state in port_matches:
            findings["ports"].append({
                "port": port,
                "state": state,
                "source": "text_extraction",
                "confidence": "medium"
            })
        
        # Dienste extrahieren
        service_keywords = ["apache", "nginx", "ftp", "ssh", "telnet", "smtp", "dns", "http", "https"]
        for service in service_keywords:
            if service in content.lower():
                findings["services"].append({
                    "name": service.upper(),
                    "source": "text_extraction",
                    "confidence": "low"
                })
        
        # Schwachstellen extrahieren
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_matches = re.findall(cve_pattern, content, re.IGNORECASE)
        for cve in cve_matches:
            findings["vulnerabilities"].append({
                "id": cve,
                "source": "text_extraction",
                "confidence": "medium"
            })
        
        # Erkenntnisse in der Datenbank speichern
        for category, entries in findings.items():
            for entry in entries:
                if entry not in self.knowledge[category]:
                    self.add_entry(category, entry)
        
        return findings

    def get_context_for_prompt(self) -> str:
        """
        Generiert einen kontextbezogenen Prompt-Abschnitt basierend auf der aktuellen Phase, Aufgabe und den Erkenntnissen.
        
        Returns:
            Ein Prompt-Text für den System-Prompt des Agenten
        """
        context = "AKTUELLER KONTEXT:\n"
        
        # Phase und Aufgabe
        if self.current_phase:
            context += f"Phase: {self.current_phase}\n"
        if self.current_task:
            context += f"Aufgabe: {self.current_task}\n"
        
        # Wichtige Erkenntnisse
        context += "\nWICHTIGE ERKENNTNISSE:\n"
        
        categories_to_include = ["hosts", "ports", "services", "vulnerabilities"]
        has_findings = False
        
        for category in categories_to_include:
            entries = self.get_entries(category, limit=5)
            if entries:
                has_findings = True
                context += f"\n{category.upper()}:\n"
                for entry in entries:
                    # Einfache Formatierung basierend auf dem Kategorie-Typ
                    if category == "hosts" and "ip" in entry:
                        context += f"- Host: {entry['ip']}\n"
                    elif category == "ports" and "port" in entry:
                        state = entry.get("state", "unbekannt")
                        context += f"- Port {entry['port']}: {state}\n"
                    elif category == "services" and "name" in entry:
                        context += f"- Dienst: {entry['name']}\n"
                    elif category == "vulnerabilities" and "id" in entry:
                        context += f"- Schwachstelle: {entry['id']}\n"
        
        if not has_findings:
            context += "Bisher wurden keine relevanten Erkenntnisse gesammelt.\n"
        
        return context

    def generate_report(self) -> str:
        """
        Generiert einen Bericht basierend auf den gesammelten Erkenntnissen.
        
        Returns:
            Ein formatierter Bericht als String
        """
        report = "# KaliYuga Penetrationstest-Bericht\n\n"
        report += f"Erstellt am: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Zusammenfassung
        report += "## Zusammenfassung\n\n"
        
        # Hosts
        hosts = self.get_entries("hosts")
        report += f"- Analysierte Hosts: {len(hosts)}\n"
        
        # Offene Ports
        ports = self.get_entries("ports")
        open_ports = [p for p in ports if p.get("state", "").lower() in ["open", "offen"]]
        report += f"- Offene Ports: {len(open_ports)}\n"
        
        # Entdeckte Dienste
        services = self.get_entries("services")
        report += f"- Entdeckte Dienste: {len(services)}\n"
        
        # Schwachstellen
        vulns = self.get_entries("vulnerabilities")
        report += f"- Gefundene Schwachstellen: {len(vulns)}\n\n"
        
        # Detaillierte Aufschlüsselung
        report += "## Detaillierte Ergebnisse\n\n"
        
        # Hosts
        report += "### Entdeckte Hosts\n\n"
        if hosts:
            for host in hosts:
                ip = host.get("ip", "Unbekannte IP")
                hostname = host.get("hostname", "Unbekannt")
                report += f"- {ip} ({hostname})\n"
        else:
            report += "Keine Hosts entdeckt.\n"
        
        report += "\n"
        
        # Offene Ports und Dienste
        report += "### Offene Ports und Dienste\n\n"
        if open_ports:
            # Gruppieren nach Host
            host_ports = {}
            for port in open_ports:
                host = port.get("host", "Unbekannt")
                if host not in host_ports:
                    host_ports[host] = []
                host_ports[host].append(port)
            
            for host, ports in host_ports.items():
                report += f"**Host: {host}**\n\n"
                for port in ports:
                    port_num = port.get("port", "Unbekannt")
                    service = port.get("service", "Unbekannt")
                    report += f"- Port {port_num}: {service}\n"
                report += "\n"
        else:
            report += "Keine offenen Ports entdeckt.\n\n"
        
        # Schwachstellen
        report += "### Identifizierte Schwachstellen\n\n"
        if vulns:
            for vuln in vulns:
                vuln_id = vuln.get("id", "Unbekannte Schwachstelle")
                severity = vuln.get("severity", "Unbekannt")
                description = vuln.get("description", "Keine Beschreibung verfügbar")
                report += f"**{vuln_id}** (Schweregrad: {severity})\n\n"
                report += f"{description}\n\n"
        else:
            report += "Keine Schwachstellen identifiziert.\n\n"
        
        # Empfehlungen
        report += "## Empfehlungen\n\n"
        report += "Basierend auf den Ergebnissen empfehlen wir die folgenden Maßnahmen:\n\n"
        
        # Automatische Empfehlungen basierend auf gefundenen Schwachstellen
        if vulns:
            for vuln in vulns:
                vuln_id = vuln.get("id", "Unbekannte Schwachstelle")
                recommendation = vuln.get("recommendation", "System patchen und aktualisieren")
                report += f"- **{vuln_id}**: {recommendation}\n"
        else:
            report += "- Regelmäßige Sicherheitsüberprüfungen durchführen\n"
            report += "- System-Updates regelmäßig installieren\n"
            report += "- Netzwerküberwachung implementieren\n"
        
        return report

    def _save_knowledge(self) -> None:
        """Speichert die Wissensdatenbank in einer JSON-Datei."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.storage_dir, f"knowledge_{timestamp}.json")
        
        try:
            with open(filename, "w") as f:
                json.dump({
                    "knowledge": self.knowledge,
                    "current_phase": self.current_phase,
                    "current_task": self.current_task,
                    "timestamp": datetime.now().isoformat()
                }, f, indent=2)
                
            logger.info(f"Wissensdatenbank in {filename} gespeichert")
        except Exception as e:
            logger.error(f"Fehler beim Speichern der Wissensdatenbank: {str(e)}")

    def _load_knowledge(self, filename: str) -> bool:
        """Lädt die Wissensdatenbank aus einer JSON-Datei."""
        try:
            with open(filename, "r") as f:
                data = json.load(f)
                
            self.knowledge = data.get("knowledge", {})
            self.current_phase = data.get("current_phase")
            self.current_task = data.get("current_task")
            
            logger.info(f"Wissensdatenbank aus {filename} geladen")
            return True
        except Exception as e:
            logger.error(f"Fehler beim Laden der Wissensdatenbank: {str(e)}")
            return False

    @classmethod
    def from_params(cls, params) -> "KaliKnowledgeBase":
        return cls(**params)

    async def execute(self, **kwargs) -> Union[str, Dict[str, Any], List[Dict[str, Any]]]:
        """
        Führt die Toolaktion aus. Dies ist die Hauptmethode, die von BaseTool aufgerufen wird.
        """
        action = kwargs.get("action")
        
        if action == "add_entry":
            category = kwargs.get("category")
            data = kwargs.get("data", {})
            if not category:
                return "Fehler: Kategorie fehlt"
            return self.add_entry(category, data)
        
        elif action == "get_entries":
            category = kwargs.get("category")
            limit = kwargs.get("limit")
            if not category:
                return "Fehler: Kategorie fehlt"
            return self.get_entries(category, limit)
        
        elif action == "search_entries":
            category = kwargs.get("category")
            query = kwargs.get("query")
            if not category or not query:
                return "Fehler: Kategorie oder Suchbegriff fehlt"
            return self.search_entries(category, query)
        
        elif action == "set_phase":
            phase = kwargs.get("phase")
            if not phase:
                return "Fehler: Phase fehlt"
            return self.set_phase(phase)
        
        elif action == "get_phase":
            phase = self.get_phase()
            return f"Aktuelle Phase: {phase}" if phase else "Keine Phase gesetzt"
        
        elif action == "set_task":
            task = kwargs.get("task")
            if not task:
                return "Fehler: Aufgabe fehlt"
            return self.set_task(task)
        
        elif action == "get_task":
            task = self.get_task()
            return f"Aktuelle Aufgabe: {task}" if task else "Keine Aufgabe gesetzt"
        
        elif action == "extract_findings":
            content = kwargs.get("content")
            if not content:
                return "Fehler: Inhalt fehlt"
            return self.extract_findings(content)
        
        elif action == "get_context_for_prompt":
            return self.get_context_for_prompt()
        
        elif action == "generate_report":
            return self.generate_report()
        
        else:
            return f"Fehler: Unbekannte Aktion '{action}'" 