import asyncio
import os
import re
import shlex
from typing import Dict, List, Optional

from app.logger import logger
from app.tool.base import BaseTool, CLIResult


class KaliLinuxTool(BaseTool):
    """
    Ein Tool für die Ausführung von Kali Linux Penetration Testing Tools direkt aus der Konsole.
    
    Dieses Tool ermöglicht den Zugriff auf Kali Linux-spezifische Funktionen und Programme
    für Penetration Testing, WLAN-Angriffe, Netzwerk-Scanning und mehr.
    """

    name: str = "kali_linux"
    description: str = """
    Führt Kali Linux Penetration Testing Tools und Befehle aus.
    
    Dieses Tool ermöglicht den Zugriff auf die vollständige Suite von Kali Linux Security Tools, darunter:
    
    1. Netzwerk-Scanning & Enumeration:
       - nmap, masscan, netdiscover, enum4linux, nikto, etc.
       
    2. Exploitation-Tools:
       - metasploit (msfconsole, msfvenom), searchsploit, etc.
       
    3. Web-Angriffs-Tools:
       - sqlmap, burpsuite, owasp-zap, dirb, gobuster, ffuf, etc.
       
    4. WLAN-Assessment:
       - aircrack-ng Suite, wifite, reaver, etc.
       
    5. Passwort-Angriffe:
       - hydra, hashcat, john, etc.
       
    6. Datensammlung & Analysetools:
       - maltego, theHarvester, etc.
       
    7. Post-Exploitation:
       - privilege escalation tools, lateral movement utils
    
    Vorsicht: Verwende diese Tools nur gegen Systeme, für die du eine ausdrückliche Genehmigung hast.
    Unbefugtes Penetration Testing ist illegal.
    """
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Der auszuführende Kali Linux Befehl. Kann direkt ein Tool aufrufen (z.B. 'nmap -sV 192.168.1.1') oder komplexere Befehle sein.",
            },
            "tool_category": {
                "type": "string",
                "description": "Optionale Kategorie des Tools für bessere Nachverfolgung und Reporting. Mögliche Werte: 'scan', 'exploit', 'web', 'wireless', 'password', 'recon', 'post_exploit'.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in Sekunden für lang laufende Befehle. Standard ist 300 (5 Minuten).",
            },
            "background": {
                "type": "boolean",
                "description": "True, wenn der Befehl im Hintergrund ausgeführt werden soll. Nützlich für kontinuierliche Tools oder lange Operationen.",
            },
        },
        "required": ["command"],
    }

    # Kali Linux tool-Befehlspfade
    _tool_paths: Dict[str, str] = {
        # Netzwerk-Scanning
        "nmap": "/usr/bin/nmap",
        "masscan": "/usr/bin/masscan",
        "netdiscover": "/usr/bin/netdiscover",
        
        # Exploitation
        "msfconsole": "/usr/bin/msfconsole",
        "msfvenom": "/usr/bin/msfvenom",
        "searchsploit": "/usr/bin/searchsploit",
        
        # Web-Angriffe
        "sqlmap": "/usr/bin/sqlmap",
        "burpsuite": "/usr/bin/burpsuite",
        "dirb": "/usr/bin/dirb",
        "gobuster": "/usr/bin/gobuster",
        "ffuf": "/usr/bin/ffuf",
        
        # WLAN
        "aircrack-ng": "/usr/bin/aircrack-ng",
        "airmon-ng": "/usr/bin/airmon-ng",
        "airodump-ng": "/usr/bin/airodump-ng",
        "wifite": "/usr/bin/wifite",
        
        # Passwort-Angriffe
        "hydra": "/usr/bin/hydra",
        "hashcat": "/usr/bin/hashcat",
        "john": "/usr/bin/john",
        
        # Datensammlung
        "theharvester": "/usr/bin/theharvester",
        
        # Post-Exploitation
        "linpeas": "/usr/bin/linpeas.sh",
        "winpeas": "/usr/bin/winpeas.exe",
    }
    
    # Liste bekannter Kali Linux Tool-Kategorien
    _tool_categories: Dict[str, List[str]] = {
        "scan": ["nmap", "masscan", "netdiscover", "enum4linux", "nikto"],
        "exploit": ["msfconsole", "msfvenom", "searchsploit", "exploit-db"],
        "web": ["sqlmap", "burpsuite", "owasp-zap", "dirb", "gobuster", "ffuf"],
        "wireless": ["aircrack-ng", "airmon-ng", "airodump-ng", "wifite", "reaver"],
        "password": ["hydra", "hashcat", "john", "crunch", "medusa"],
        "recon": ["maltego", "theharvester", "recon-ng", "osint"],
        "post_exploit": ["linpeas", "winpeas", "mimikatz", "empire", "bloodhound"],
    }
    
    # Tracking der laufenden Hintergrundprozesse
    _background_processes: Dict[str, asyncio.subprocess.Process] = {}
    
    process: Optional[asyncio.subprocess.Process] = None
    current_path: str = os.getcwd()
    lock: asyncio.Lock = asyncio.Lock()

    async def execute(
        self,
        command: str,
        tool_category: Optional[str] = None,
        timeout: int = 300,
        background: bool = False,
    ) -> CLIResult:
        """
        Führt einen Kali Linux Befehl aus.
        
        Args:
            command: Der auszuführende Befehl
            tool_category: Optionale Kategorie für Tracking und Dokumentation
            timeout: Timeout in Sekunden
            background: True, wenn Befehl im Hintergrund laufen soll
            
        Returns:
            CLIResult mit Ausgabe und Fehlern
        """
        sanitized_command = self._sanitize_command(command)
        
        # Extrahiere das Haupttool aus dem Befehl für Logging und Kategorisierung
        main_tool = self._extract_tool_name(sanitized_command)
        
        # Validiere und erweitere den Tool-Pfad
        if main_tool and main_tool in self._tool_paths:
            # Ersetze das Tool mit dem vollen Pfad, falls nicht bereits angegeben
            if not sanitized_command.startswith("/"):
                path_pattern = r"^" + re.escape(main_tool)
                sanitized_command = re.sub(
                    path_pattern, self._tool_paths[main_tool], sanitized_command, count=1
                )
                
        # Bestimme Kategorie (falls nicht angegeben)
        if not tool_category and main_tool:
            for category, tools in self._tool_categories.items():
                if main_tool in tools:
                    tool_category = category
                    break
        
        # Logge den Befehl mit Kategorie
        log_prefix = f"[{tool_category or 'kali'}]" if tool_category else "[kali]"
        logger.info(f"{log_prefix} Führe aus: {sanitized_command}")
        
        # Hintergrundausführung
        if background:
            return await self._run_background(sanitized_command, main_tool)
        
        # Normale Ausführung
        return await self._run_command(sanitized_command, timeout)
    
    async def _run_command(self, command: str, timeout: int) -> CLIResult:
        """Führt einen Befehl im Vordergrund mit Timeout aus."""
        async with self.lock:
            try:
                start_time = asyncio.get_event_loop().time()
                
                # Führe Befehl aus
                self.process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.current_path,
                )
                
                # Warte auf Ergebnis mit Timeout
                try:
                    stdout, stderr = await asyncio.wait_for(
                        self.process.communicate(), timeout=timeout
                    )
                    
                    execution_time = asyncio.get_event_loop().time() - start_time
                    
                    return CLIResult(
                        output=f"[Ausgeführt in {execution_time:.2f}s]\n{stdout.decode().strip()}",
                        error=stderr.decode().strip(),
                    )
                except asyncio.TimeoutError:
                    # Bei Timeout: Prozess beenden und Nachricht zurückgeben
                    if self.process and self.process.returncode is None:
                        self.process.terminate()
                        try:
                            await asyncio.wait_for(self.process.wait(), timeout=5.0)
                        except asyncio.TimeoutError:
                            # Hart beenden
                            self.process.kill()
                            
                    return CLIResult(
                        output="",
                        error=f"Befehlsausführung von '{command}' hat das Timeout von {timeout}s überschritten. Prozess wurde beendet.",
                    )
            except Exception as e:
                return CLIResult(output="", error=f"Fehler bei der Ausführung: {str(e)}")
            finally:
                self.process = None
    
    async def _run_background(self, command: str, process_name: Optional[str] = None) -> CLIResult:
        """Führt einen Befehl im Hintergrund aus."""
        # Generiere einen Prozessnamen, falls keiner angegeben
        if process_name is None:
            process_name = f"bg_process_{len(self._background_processes) + 1}"
            
        # Bereite Befehl vor (umleiten von stdout/stderr in Datei)
        timestamp = asyncio.get_event_loop().time()
        log_file = f"/tmp/kali_bg_{process_name}_{int(timestamp)}.log"
        bg_command = f"{command} > {log_file} 2>&1 &"
        
        try:
            # Führe im Hintergrund aus
            process = await asyncio.create_subprocess_shell(
                bg_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.current_path,
            )
            
            # Speichere den Prozess für späteres Tracking
            self._background_processes[process_name] = process
            
            return CLIResult(
                output=f"Befehl '{command}' wird im Hintergrund ausgeführt. Prozess-ID: {process_name}. Logdatei: {log_file}",
                error="",
            )
        except Exception as e:
            return CLIResult(
                output="",
                error=f"Fehler beim Starten des Hintergrundprozesses: {str(e)}",
            )
    
    @staticmethod
    def _extract_tool_name(command: str) -> Optional[str]:
        """Extrahiert den Haupttoolnamen aus einem Befehl."""
        if not command:
            return None
            
        # Einfache Extraktion des ersten Wortes
        parts = shlex.split(command)
        if not parts:
            return None
            
        # Entferne den Pfad, falls vorhanden
        tool = os.path.basename(parts[0])
        return tool
    
    @staticmethod
    def _sanitize_command(command: str) -> str:
        """
        Sanitize den Befehl für sichere Ausführung.
        Bei einem Penetration Testing Tool ermöglichen wir mehr, 
        aber implementieren grundlegende Sicherheitsmaßnahmen.
        """
        # Entferne schädliche Verkettungen wie ";rm -rf /"
        dangerous_patterns = [
            r';(\s*rm\s+-rf\s+/)',
            r'`.*rm\s+-rf\s+/.*`',
            r'\|\s*rm\s+-rf\s+/',
        ]
        
        command_to_check = command.lower()
        for pattern in dangerous_patterns:
            if re.search(pattern, command_to_check):
                raise ValueError(f"Potenziell gefährlicher Befehl erkannt: {command}")
                
        return command
    
    async def check_tool_availability(self) -> Dict[str, bool]:
        """
        Überprüft die Verfügbarkeit von Kali Linux Tools und
        gibt ein Dictionary mit Tools und ihrem Status zurück.
        """
        results = {}
        for tool, path in self._tool_paths.items():
            command = f"which {tool}"
            result = await self._run_command(command, timeout=5)
            results[tool] = len(result.error) == 0 and path in result.output
            
        return results
        
    async def get_running_background_processes(self) -> CLIResult:
        """Gibt Information über laufende Hintergrundprozesse zurück."""
        output = "Laufende Hintergrundprozesse:\n"
        
        # Überprüfe jeden gespeicherten Prozess
        processes_to_remove = []
        for name, process in self._background_processes.items():
            if process.returncode is not None:
                processes_to_remove.append(name)
                output += f"- {name}: Beendet (Rückgabecode: {process.returncode})\n"
            else:
                output += f"- {name}: Läuft noch\n"
                
        # Entferne beendete Prozesse
        for name in processes_to_remove:
            del self._background_processes[name]
            
        if not self._background_processes and not processes_to_remove:
            output = "Keine Hintergrundprozesse laufen aktuell."
            
        return CLIResult(output=output, error="")
        
    async def terminate_background_process(self, process_name: str) -> CLIResult:
        """Beendet einen im Hintergrund laufenden Prozess."""
        if process_name not in self._background_processes:
            return CLIResult(
                output="",
                error=f"Hintergrundprozess '{process_name}' nicht gefunden.",
            )
            
        process = self._background_processes[process_name]
        if process.returncode is not None:
            del self._background_processes[process_name]
            return CLIResult(
                output=f"Prozess '{process_name}' wurde bereits beendet (Rückgabecode: {process.returncode}).",
                error="",
            )
            
        # Beende den Prozess
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
            result = CLIResult(
                output=f"Prozess '{process_name}' wurde erfolgreich beendet.",
                error="",
            )
        except asyncio.TimeoutError:
            process.kill()
            result = CLIResult(
                output=f"Prozess '{process_name}' musste hart beendet werden (kill).",
                error="",
            )
            
        # Entferne den Prozess aus der Tracking-Liste
        del self._background_processes[process_name]
        return result 