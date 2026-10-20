import os
from typing import List

from amsatop import Htop, Process, TaskType

# Máscara de bits de Linux para detectar Kernel Threads
PF_KTHREAD = 0x00200000


class Amsatop(Htop):
    def __init__(self):
        super().__init__()

    def _parse_processes(self, include_priority: bool = False) -> List[Process]:
        """Función auxiliar para obtener los procesos, threads y kthreads.

        Si include_priority es True, lee e incluye la prioridad.
        """
        processes: List[Process] = []

        try:
            entries = os.listdir(self.proc_folder)
        except (FileNotFoundError, PermissionError):
            return processes

        pids = [entry for entry in entries if entry.isdigit()]

        for pid in pids:
            try:
                proc_path = os.path.join(self.proc_folder, pid)
                stat_file = os.path.join(proc_path, "stat")
                comm_file = os.path.join(proc_path, "comm")

                if not os.path.exists(stat_file):
                    continue

                with open(stat_file, "r") as f:
                    stat_content = f.read()

                lpar_index = stat_content.find("(")
                rpar_index = stat_content.rfind(")")
                if lpar_index == -1 or rpar_index == -1:
                    continue

                command = stat_content[lpar_index + 1 : rpar_index]

                if os.path.exists(comm_file):
                    try:
                        with open(comm_file, "r") as f:
                            comm_val = f.read().strip()
                            if comm_val:
                                command = comm_val
                    except (FileNotFoundError, PermissionError, ProcessLookupError):
                        pass

                after_comm = stat_content[rpar_index + 1 :].split()
                flags = 0
                priority_val = None

                if len(after_comm) >= 7:
                    flags = int(after_comm[6])

                # En /proc/{pid}/stat, la prioridad es el campo 18 (índice 15 tras la comanda)
                if include_priority and len(after_comm) >= 16:
                    priority_val = int(after_comm[15])

                # Comprobar si es Kernel Thread
                if (flags & PF_KTHREAD) != 0:
                    processes.append(
                        Process(
                            pid=int(pid),
                            command=command,
                            type=TaskType.KTHREAD,
                            priority=priority_val,
                        )
                    )
                    continue

                # Proceso normal
                processes.append(
                    Process(
                        pid=int(pid),
                        command=command,
                        type=TaskType.PROCESS,
                        priority=priority_val,
                    )
                )

                # Threads secundarios
                task_folder = os.path.join(proc_path, "task")
                if os.path.exists(task_folder):
                    try:
                        tids = os.listdir(task_folder)
                    except (FileNotFoundError, PermissionError):
                        tids = []

                    for tid in tids:
                        if tid.isdigit() and tid != pid:
                            thread_stat_file = os.path.join(task_folder, tid, "stat")
                            thread_comm_file = os.path.join(task_folder, tid, "comm")

                            thread_cmd = None
                            thread_priority = None

                            if os.path.exists(thread_comm_file):
                                try:
                                    with open(thread_comm_file, "r") as f:
                                        thread_cmd = f.read().strip()
                                except (FileNotFoundError, PermissionError, ProcessLookupError):
                                    pass

                            if os.path.exists(thread_stat_file):
                                try:
                                    with open(thread_stat_file, "r") as f:
                                        t_content = f.read()
                                        tl = t_content.find("(")
                                        tr = t_content.rfind(")")
                                        if tl != -1 and tr != -1:
                                            if thread_cmd is None:
                                                thread_cmd = t_content[tl + 1 : tr]
                                            t_after = t_content[tr + 1 :].split()
                                            if include_priority and len(t_after) >= 16:
                                                thread_priority = int(t_after[15])
                                except (FileNotFoundError, PermissionError, ProcessLookupError):
                                    pass

                            if thread_cmd is None:
                                continue

                            processes.append(
                                Process(
                                    pid=int(tid),
                                    command=thread_cmd,
                                    type=TaskType.THREAD,
                                    priority=thread_priority,
                                )
                            )

            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue

        return processes

    def get_processes(self) -> List[Process]:
        return self._parse_processes(include_priority=False)

    def get_priorities(self) -> List[Process]:
        return self._parse_processes(include_priority=True)

    def get_hup(self) -> List[Process]:
        raise NotImplementedError("Prac-2.3 implementation needed")
