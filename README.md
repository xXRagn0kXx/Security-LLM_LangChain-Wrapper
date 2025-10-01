


# Security-LLM_LangChain-Wrapper
## Fase 0 prueba de ejecucion rkllm
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wrapper rkllm con Qwen3 usando pexpect para LangChain:

- Envía un prompt
- Captura toda la salida en logs con fecha/hora
- Detecta automáticamente el final de la respuesta al ver el prompt "You:"
- Cierra limpiamente con 'quit' y espera EOF
"""

import os
import datetime
import pexpect

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "rknnllm-models",
    "Qwen3-4B-rk3588-1.2.1",
    "Qwen3-4B-rk3588-w8a8-opt-1-hybrid-ratio-0.0.rkllm"
)

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

PROMPT = "Hola, ¿puedes contar del 1 al 10?"
CONTEXT_SIZE = 512
MAX_OUTPUT = 2048

def run_rkllm(prompt: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file_path = os.path.join(LOG_DIR, f"qwen3_log_{timestamp}.txt")

    # Lanzamos rkllm en modo TTY con pexpect
    child = pexpect.spawn(
        f"/usr/bin/rkllm {MODEL_PATH} {CONTEXT_SIZE} {MAX_OUTPUT}",
        encoding='utf-8',
        timeout=None
    )

    with open(log_file_path, "w", encoding="utf-8") as log_file:
        # Esperamos primer prompt "You:" inicial
        child.expect("You:")

        # Enviamos nuestro prompt
        child.sendline(prompt)

        # Esperamos hasta el siguiente prompt "You:" que indica fin de respuesta
        child.expect("You:")
        respuesta = child.before  # Contenido generado por el modelo

        # Guardamos la respuesta en el log y mostramos en pantalla
        print(respuesta, end="")
        log_file.write(respuesta)
        log_file.flush()

        # Cerramos el modelo limpiamente
        try:
            child.sendline("quit")
            child.expect(pexpect.EOF)  # Esperamos que el proceso termine
        except pexpect.ExceptionPexpect:
            # Si falla, hacemos un close forzado
            child.close(force=True)

    print(f"\nRespuesta guardada en {log_file_path}")

if __name__ == "__main__":
    run_rkllm(PROMPT)
```
por consola
```python

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wrapper rkllm con Qwen3:

- Envía un prompt
- Guarda toda la salida en logs con fecha/hora en tiempo real
- Cierra automáticamente el modelo al terminar
"""

import subprocess
import datetime
import os
import sys
import select
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "rknnllm-models",
    "Qwen3-4B-rk3588-1.2.1",
    "Qwen3-4B-rk3588-w8a8-opt-1-hybrid-ratio-0.0.rkllm"
)

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

PROMPT = "Hola, ¿puedes contar del 1 al 10?"
CONTEXT_SIZE = 512
MAX_OUTPUT = 2048
TIMEOUT = 20  # segundos máximos de espera para la respuesta

def run_rkllm(prompt: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file_path = os.path.join(LOG_DIR, f"qwen3_log_{timestamp}.txt")

    with open(log_file_path, "w", encoding="utf-8", buffering=1) as log_file:
        # Lanzamos rkllm como subproceso
        process = subprocess.Popen(
            ["/usr/bin/rkllm", MODEL_PATH, str(CONTEXT_SIZE), str(MAX_OUTPUT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Enviamos el prompt
        process.stdin.write(prompt + "\n")
        process.stdin.flush()

        start_time = time.time()
        while True:
            ready, _, _ = select.select([process.stdout], [], [], 0.1)
            if ready:
                line = process.stdout.readline()
                if line:
                    print(line, end="")
                    log_file.write(line)
                    log_file.flush()
            # Timeout para cerrar automáticamente
            if time.time() - start_time > TIMEOUT:
                break

        # Cerramos el modelo
        process.stdin.close()
        process.kill()
        process.wait()

    print(f"\nRespuesta guardada en {log_file_path}")

if __name__ == "__main__":
    run_rkllm(PROMPT)


```
## Fase 1 Selector de logs 
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pre-procesador y Tracker Incremental de Logs de Seguridad
Genera archivo JSON de tareas para un análisis LLM posterior
"""

import os
import json
import datetime
import re
from pathlib import Path
from typing import Dict, List, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
SECURITY_LOG_DIR = os.path.join(LOG_DIR, "security_analysis")
STATE_FILE = os.path.join(SECURITY_LOG_DIR, "log_state.json")
# Nuevo archivo de salida para las tareas de análisis del LLM
ANALYSIS_TASK_FILE = os.path.join(SECURITY_LOG_DIR, "llm_analysis_tasks.json") 

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(SECURITY_LOG_DIR, exist_ok=True)

# Patrones para clasificar logs por prioridad DINÁMICAMENTE
PRIORITY_PATTERNS = {
    'critical': [
        r'auth\.log',
        r'kern\.log',
        r'crowdsec.*\.log',
        r'security\.log',
        r'fail2ban\.log',
        r'ufw\.log'
    ],
    'important': [
        r'syslog',
        r'cron\.log',
        r'daemon\.log',
        r'messages',
        r'apache.*\.log',
        r'nginx.*\.log'
    ],
    'informational': [
        r'user\.log',
        r'monitor\.log',
        r'debug\.log'
    ]
}

# Patrones de amenazas para pre-filtrado
THREAT_PATTERNS = [
    r'failed password',
    r'authentication failure',
    r'invalid user',
    r'refused connect',
    r'kernel panic',
    r'segfault',
    r'out of memory',
    r'connection refused',
    r'banned',
    r'attack',
    r'exploit',
    r'suspicious',
    r'unauthorized',
    r'denied',
    r'error.*critical',
    r'warning.*security'
]

class LogDiscovery:
    """Descubre y clasifica logs dinámicamente"""
    
    def __init__(self, base_path: str = '/var/log'):
        self.base_path = base_path
    
    def discover_all_logs(self) -> List[Dict]:
        """
        Descubre TODOS los archivos .log en /var/log
        Retorna lista de diccionarios con información de cada log
        """
        print(f"\n🔍 Etapa 1: Escaneando {self.base_path}...")
        log_files = []
        
        try:
            # Ejecutar ls -l equivalente
            # Se usa Path.glob para evitar problemas con logs rotados (ej: syslog.1)
            # y solo enfocarse en los logs activos (.log)
            for file_path in Path(self.base_path).glob('*.log'):
                if file_path.is_file():
                    try:
                        stat = file_path.stat()
                        log_info = {
                            'path': str(file_path),
                            'name': file_path.name,
                            'size': stat.st_size,
                            'mtime': stat.st_mtime,
                            'mtime_human': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                            'owner': stat.st_uid,
                            'readable': os.access(file_path, os.R_OK)
                        }
                        log_files.append(log_info)
                        print(f"   📄 Encontrado: {file_path.name} ({self._format_size(stat.st_size)})")
                    except PermissionError:
                        print(f"   ⚠️  Permiso denegado: {file_path.name}")
                        continue
            
            print(f"\n   ✅ Total de logs descubiertos: {len(log_files)}")
            return log_files
            
        except PermissionError:
            print(f"   ❌ Error: No se puede acceder a {self.base_path}")
            return []
    
    def _format_size(self, size_bytes: int) -> str:
        """Formatea tamaño en bytes a formato legible"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}TB"
    
    def classify_log(self, log_name: str) -> str:
        """
        Clasifica un log por prioridad basado en su nombre
        Retorna: 'critical', 'important', 'informational' o 'unknown'
        """
        for priority, patterns in PRIORITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, log_name, re.IGNORECASE):
                    return priority
        return 'unknown'
    
    def categorize_logs(self, log_files: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Categoriza todos los logs descubiertos por prioridad
        """
        categorized = {
            'critical': [],
            'important': [],
            'informational': [],
            'unknown': []
        }
        
        for log_info in log_files:
            priority = self.classify_log(log_info['name'])
            categorized[priority].append(log_info)
        
        # Mostrar resumen de categorización
        print("\n📊 Categorización por prioridad:")
        for priority in ['critical', 'important', 'informational', 'unknown']:
            if categorized[priority]:
                print(f"   🔴 {priority.upper()}: {len(categorized[priority])} logs")
                # Solo mostrar los nombres sin listar todos para logs grandes
                if len(categorized[priority]) < 10:
                    for log in categorized[priority]:
                        print(f"      - {log['name']}")
                else:
                    print(f"      - Mostrando los primeros 5: {[l['name'] for l in categorized[priority][:5]]}...")

        return categorized

class LogTracker:
    """Gestiona el estado y tracking de logs"""
    
    def __init__(self, state_file: str):
        self.state_file = state_file
        self.state = self.load_state()
    
    def load_state(self) -> Dict:
        """Carga el estado previo de los logs"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_state(self):
        """Guarda el estado actual"""
        with open(self.state_file, 'w') as f:
            # Usar 'ensure_ascii=False' para asegurar caracteres especiales correctos
            json.dump(self.state, f, indent=2, ensure_ascii=False)
    
    def has_changed(self, log_info: Dict) -> Tuple[bool, int]:
        """
        Verifica si un log ha cambiado desde la última lectura.
        Retorna: (cambió: bool, bytes_desde: int)
        """
        log_path = log_info['path']
        current_size = log_info['size']
        current_mtime = log_info['mtime']
        
        if not log_info['readable']:
            return False, 0
        
        if log_path not in self.state:
            # Primera vez que vemos este log - es NUEVO
            print(f"   🆕 LOG NUEVO DETECTADO: {log_info['name']}")
            return True, 0
        
        previous = self.state[log_path]
        previous_size = previous.get('size', 0)
        previous_mtime = previous.get('mtime', 0)
        
        # 1. Detección de CRECIMIENTO (AUMENTO de bytes)
        if current_size > previous_size:
            print(f"   📈 {log_info['name']}: creció de {previous_size} a {current_size} bytes")
            return True, previous_size
            
        # 2. Detección de ROTACIÓN/TRUNCAMIENTO (DISMINUCIÓN de bytes)
        elif current_size < previous_size:
            print(f"   🔄 {log_info['name']}: rotado/truncado (era {previous_size}, ahora {current_size})")
            return True, 0
            
        # 3. Detección por MTIME (mismo número de bytes, pero modificado)
        elif current_mtime > previous_mtime:
             print(f"   ✏️ {log_info['name']}: contenido modificado (mtime cambió, tamaño igual)")
             return True, 0 # Re-analizar desde el inicio por seguridad
        
        # 4. Sin cambios
        return False, 0
    
    def update_log_state(self, log_info: Dict):
        """Actualiza el estado de un log después de procesarlo"""
        log_path = log_info['path']
        self.state[log_path] = {
            'size': log_info['size'],
            'mtime': log_info['mtime'],
            'last_check': datetime.datetime.now().isoformat(),
            'name': log_info['name']
        }
    
    def clean_stale_entries(self, current_logs: List[Dict]):
        """
        Limpia entradas del estado de logs que ya no existen
        """
        current_paths = {log['path'] for log in current_logs}
        stale_paths = [path for path in self.state.keys() if path not in current_paths]
        
        if stale_paths:
            print(f"\n🧹 Limpiando {len(stale_paths)} entradas obsoletas del estado:")
            for path in stale_paths:
                print(f"   - {os.path.basename(path)}")
                del self.state[path]
            self.save_state()

class LogProcessor:
    """Pre-procesa logs (lectura, filtrado de amenazas)"""
    
    def __init__(self):
        # Compilar la expresión regular de amenazas
        self.threat_regex = re.compile('|'.join(THREAT_PATTERNS), re.IGNORECASE)
        # Límite de líneas sospechosas a incluir en la tarea para el LLM
        self.MAX_SUSPICIOUS_LINES = 100 
    
    def read_log_incremental(self, log_path: str, from_byte: int, max_lines: int = 1000) -> str:
        """Lee un log desde una posición específica, limitando las líneas para evitar sobrecarga"""
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(from_byte)
                lines = []
                for _ in range(max_lines):
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line)
                return ''.join(lines)
        except Exception as e:
            return f"Error leyendo {log_path}: {str(e)}"
    
    def prefilter_suspicious_lines(self, content: str) -> Tuple[List[str], int]:
        """
        Pre-filtra líneas sospechosas basadas en THREAT_PATTERNS
        Retorna: (líneas_sospechosas, total_líneas)
        """
        lines = content.split('\n')
        suspicious = []
        
        for line in lines:
            if self.threat_regex.search(line):
                suspicious.append(line)
        
        return suspicious, len(lines)
    
    def create_llm_task_context(self, log_name: str, suspicious_lines: List[str], total_lines: int) -> str:
        """
        Genera el contexto de texto para que el LLM lo analice
        """
        suspicious_content = '\n'.join(suspicious_lines[:self.MAX_SUSPICIOUS_LINES])
        
        context = f"""Analiza las siguientes líneas sospechosas detectadas en el log '{log_name}'.
Estas líneas fueron pre-filtradas por contener patrones de seguridad relevantes.

Prioridad de análisis: {log_name} (se recomienda priorizar).
Líneas totales revisadas en este incremento: {total_lines}
Líneas sospechosas encontradas: {len(suspicious_lines)}
Límite de líneas sospechosas para el análisis: {self.MAX_SUSPICIOUS_LINES}

Contenido sospechoso a analizar:
--- INICIO ---
{suspicious_content}
--- FIN ---

Tarea para el LLM: Proporciona un análisis conciso en español (máximo 400 palabras) que incluya:
1. ¿Son amenazas reales, intentos de ataque o falsos positivos?
2. Nivel de severidad (Bajo/Medio/Alto/Crítico) y justificación.
3. Acción recomendada para mitigar o investigar.
4. Resumen ejecutivo en una línea para el reporte."""

        return context
    
    def process_log_incremental(self, log_info: Dict, from_byte: int) -> Dict:
        """Procesa un log de forma incremental"""
        log_path = log_info['path']
        log_name = log_info['name']
        
        print(f"\n📋 Procesando: {log_name} (desde byte {from_byte})")
        
        # Leer contenido nuevo
        content = self.read_log_incremental(log_path, from_byte)
        
        if content.startswith("Error"):
            return {
                'log': log_path,
                'log_name': log_name,
                'status': 'error',
                'message': content,
                'requires_analysis': False
            }
        
        # Pre-filtrar líneas sospechosas
        suspicious_lines, total_lines = self.prefilter_suspicious_lines(content)
        
        print(f"   📊 Líneas totales: {total_lines}, Sospechosas: {len(suspicious_lines)}")
        
        # Si no hay líneas sospechosas, no requerir análisis LLM
        if len(suspicious_lines) == 0:
            return {
                'log': log_path,
                'log_name': log_name,
                'status': 'clean',
                'message': 'No se detectaron patrones sospechosos',
                'requires_analysis': False,
                'lines_checked': total_lines
            }
        
        # Generar contexto de análisis para el LLM
        llm_context = self.create_llm_task_context(log_name, suspicious_lines, total_lines)
        
        return {
            'log': log_path,
            'log_name': log_name,
            'status': 'pending_analysis', # Nuevo estado: Pendiente de LLM
            'suspicious_count': len(suspicious_lines),
            'total_lines': total_lines,
            'llm_context': llm_context, # El campo que usará la siguiente chain
            'requires_analysis': True
        }

def save_analysis_tasks(results: List[Dict]):
    """Guarda las tareas de análisis pendientes del LLM en un archivo JSON"""
    tasks_to_analyze = [
        {
            'task_id': f"{r['log_name']}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
            'log_name': r['log_name'],
            'priority': r['priority'],
            'log_path': r['log'],
            'suspicious_count': r['suspicious_count'],
            'total_lines_checked': r['total_lines'],
            'llm_context': r['llm_context']
        }
        for r in results if r['requires_analysis']
    ]
    
    if tasks_to_analyze:
        try:
            with open(ANALYSIS_TASK_FILE, 'w', encoding='utf-8') as f:
                json.dump(
                    {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'total_tasks': len(tasks_to_analyze),
                        'tasks': tasks_to_analyze
                    }, 
                    f, 
                    indent=2,
                    ensure_ascii=False # Asegura el correcto almacenamiento de caracteres especiales
                )
            print(f"\n✅ Tareas de análisis LLM guardadas en: {ANALYSIS_TASK_FILE} ({len(tasks_to_analyze)} tareas)")
        except Exception as e:
            print(f"❌ Error al guardar las tareas de análisis en JSON: {e}")
    else:
        print("\nℹ️  No se generaron tareas de análisis para el LLM.")


def generate_smart_security_report():
    """Genera un reporte de pre-análisis de seguridad y tareas LLM"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    # El reporte ahora solo es de pre-análisis
    report_file = os.path.join(SECURITY_LOG_DIR, f"pre_analysis_report_{timestamp}.txt")
    
    print("=" * 80)
    print("🔍 SISTEMA INTELIGENTE DE PRE-ANÁLISIS DE LOGS (Generador de Tareas LLM)")
    print("=" * 80)
    
    # Inicializar componentes
    discovery = LogDiscovery()
    tracker = LogTracker(STATE_FILE)
    processor = LogProcessor() # Renombrado de LogAnalyzer
    
    # Etapa 1: Discovery - SIEMPRE escanea el directorio
    all_logs = discovery.discover_all_logs()
    
    if not all_logs:
        print("❌ No se encontraron logs o no hay permisos de lectura")
        return None
    
    # Categorizar por prioridad
    categorized = discovery.categorize_logs(all_logs)
    
    # Limpiar entradas obsoletas del estado
    tracker.clean_stale_entries(all_logs)
    
    # Etapa 2: Detectar cambios
    print("\n🔄 Etapa 2: Detectando cambios...")
    changed_logs = []
    
    # Procesar en orden de prioridad
    for priority in ['critical', 'important', 'informational', 'unknown']:
        for log_info in categorized[priority]:
            has_changed, from_byte = tracker.has_changed(log_info)
            if has_changed:
                changed_logs.append((log_info, from_byte, priority))
    
    if not changed_logs:
        print("   ℹ️  No se detectaron cambios en ningún log")
        return None
    
    print(f"\n   📊 Total de logs modificados: {len(changed_logs)}")
    
    # Etapa 3: Procesamiento incremental
    print("\n🔬 Etapa 3: Procesamiento incremental de logs modificados...")
    results = []
    
    for log_info, from_byte, priority in changed_logs:
        result = processor.process_log_incremental(log_info, from_byte)
        result['priority'] = priority
        results.append(result)
        tracker.update_log_state(log_info)
    
    # Etapa 4: Guardar estado y tareas
    tracker.save_state()
    save_analysis_tasks(results)
    
    # Etapa 5: Generar reporte de pre-análisis
    print("\n📝 Etapa 5: Generando reporte de pre-análisis...")
    
    with open(report_file, "w", encoding="utf-8") as report:
        report.write("=" * 80 + "\n")
        report.write("REPORTE DE PRE-ANÁLISIS DE SEGURIDAD\n")
        report.write(f"Generado: {datetime.datetime.now()}\n")
        report.write("=" * 80 + "\n\n")
        
        # Estadísticas generales
        report.write("📊 ESTADÍSTICAS GENERALES\n")
        report.write("-" * 50 + "\n")
        report.write(f"Total de logs detectados en /var/log: {len(all_logs)}\n")
        report.write(f"Logs con cambios: {len(changed_logs)}\n")
        
        pending_count = sum(1 for r in results if r['requires_analysis'])
        clean_count = sum(1 for r in results if r['status'] == 'clean')
        
        report.write(f"Logs que generaron tareas de análisis LLM: {pending_count}\n")
        report.write(f"Logs sin anomalías (en el incremento): {clean_count}\n\n")
        
        # Mostrar distribución de logs descubiertos
        report.write("🔍 LOGS DESCUBIERTOS POR CATEGORÍA\n")
        report.write("-" * 50 + "\n")
        for priority in ['critical', 'important', 'informational', 'unknown']:
            count = len(categorized[priority])
            if count > 0:
                report.write(f"{priority.upper()}: {count} logs\n")
                for log in categorized[priority]:
                    report.write(f"  - {log['name']} ({log['size']} bytes)\n")
        report.write("\n")
        
        # Resultados por prioridad
        for priority in ['critical', 'important', 'informational', 'unknown']:
            priority_results = [r for r in results if r.get('priority') == priority]
            
            if priority_results:
                report.write("=" * 80 + "\n")
                report.write(f"🔴 LOGS {priority.upper()} (Resultados de Pre-Análisis)\n")
                report.write("=" * 80 + "\n\n")
                
                for result in priority_results:
                    report.write(f"📄 {result['log_name']}\n")
                    report.write(f"   Ruta: {result['log']}\n")
                    report.write("-" * 50 + "\n")
                    
                    if result['status'] == 'clean':
                        report.write(f"✅ Estado: Limpio\n")
                        report.write(f"   Líneas revisadas: {result.get('lines_checked', 0)}\n\n")
                    
                    elif result['status'] == 'pending_analysis':
                        report.write(f"⚠️  Estado: Tarea LLM generada\n")
                        report.write(f"   Líneas sospechosas: {result['suspicious_count']}/{result['total_lines']}\n\n")
                        report.write("CONTEXTO PARA LLM (Resumen de Tarea):\n")
                        report.write(result['llm_context'][:500] + "...\n\n") # Mostrar solo un fragmento
                    
                    elif result['status'] == 'error':
                        report.write(f"❌ Error: {result['message']}\n\n")
        
    print(f"✅ Reporte de pre-análisis guardado en: {report_file}")
    return report_file

def main():
    """Función principal"""
    try:
        report_file = generate_smart_security_report()
        
        if report_file:
            print("\n" + "=" * 80)
            print("✅ PRE-ANÁLISIS Y GENERACIÓN DE TAREAS COMPLETADOS")
            print("=" * 80)
            print(f"📄 Reporte de Pre-Análisis: {report_file}")
            print(f"💾 Estado de Logs guardado en: {STATE_FILE}")
            print(f"📄 Tareas LLM guardadas en: {ANALYSIS_TASK_FILE}")
        else:
            print("\n" + "=" * 80)
            print("ℹ️  NO SE REQUIRIÓ PROCESAMIENTO")
            print("=" * 80)
            print("No se detectaron cambios en los logs desde la última ejecución")
            
    except Exception as e:
        print(f"\n❌ Error durante el pre-análisis: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
```
