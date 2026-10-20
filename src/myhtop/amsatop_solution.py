import os
from typing import List

from amsatop import Htop, Process, TaskType

# Màscara de bits de Linux per detectar Kernel Threads
PF_KTHREAD = 0x00200000


class Amsatop(Htop):
    def __init__(self):
        super().__init__()

    def get_processes(self) -> List[Process]:
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

                # Extreure el nom de la comanda compresa entre '(' i ')' a /proc/{pid}/stat
                command = stat_content[lpar_index + 1 : rpar_index]

                # Si existeix el fitxer 'comm', utilitza'l si conté dades
                if os.path.exists(comm_file):
                    try:
                        with open(comm_file, "r") as f:
                            comm_val = f.read().strip()
                            if comm_val:
                                command = comm_val
                    except (FileNotFoundError, PermissionError, ProcessLookupError):
                        pass

                # Després del parèntesi de tancament, parsejar els valors restants
                after_comm = stat_content[rpar_index + 1 :].split()
                flags = 0
                if len(after_comm) >= 7:
                    flags = int(after_comm[6])

                # Comprovar si és un Kernel Thread (kthread)
                if (flags & PF_KTHREAD) != 0:
                    processes.append(
                        Process(
                            pid=int(pid),
                            command=command,
                            type=TaskType.KTHREAD,
                            priority=None,
                        )
                    )
                    continue

                # Procés normal (PROCESS)
                processes.append(
                    Process(
                        pid=int(pid),
                        command=command,
                        type=TaskType.PROCESS,
                        priority=None,
                    )
                )

                # Cercar threads secundaris a la carpeta task
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

                            if os.path.exists(thread_comm_file):
                                try:
                                    with open(thread_comm_file, "r") as f:
                                        thread_cmd = f.read().strip()
                                except (FileNotFoundError, PermissionError, ProcessLookupError):
                                    pass

                            if thread_cmd is None and os.path.exists(thread_stat_file):
                                try:
                                    with open(thread_stat_file, "r") as f:
                                        t_content = f.read()
                                        tl = t_content.find("(")
                                        tr = t_content.rfind(")")
                                        if tl != -1 and tr != -1:
                                            thread_cmd = t_content[tl + 1 : tr]
                                except (FileNotFoundError, PermissionError, ProcessLookupError):
                                    pass

                            # Si el thread ha finalitzat, no tindrà ni comm ni stat actius
                            if thread_cmd is None:
                                continue

                            processes.append(
                                Process(
                                    pid=int(tid),
                                    command=thread_cmd,
                                    type=TaskType.THREAD,
                                    priority=None,
                                )
                            )

            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue

        return processes

    def get_priorities(self) -> List[Process]:
        raise NotImplementedError("Prac-2.2 implementation needed")

    def get_hup(self) -> List[Process]:
        raise NotImplementedError("Prac-2.3 implementation needed")
