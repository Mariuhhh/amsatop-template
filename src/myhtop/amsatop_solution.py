import os
from typing import List

from amsatop import Htop, Process, TaskType

# Màscara de bits de Linux per detectar Kernel Threads
PF_KTHREAD = 0x00200000

# Màscara de bits per al senyal 1 (SIGHUP): 2^(1-1) = 1
SIGHUP_MASK = 1


class Amsatop(Htop):
    def __init__(self):
        super().__init__()

    def _is_sighup_ignored(self, status_path: str) -> bool:
        """Llegeix el fitxer status i comprova si el senyal SIGHUP (1) està a SigIgn."""
        if not os.path.exists(status_path):
            return False
        try:
            with open(status_path, "r") as f:
                for line in f:
                    if line.startswith("SigIgn:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            sig_ign_hex = parts[1]
                            sig_ign_val = int(sig_ign_hex, 16)
                            return (sig_ign_val & SIGHUP_MASK) != 0
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            pass
        return False

    def _parse_processes(
        self, include_priority: bool = False, filter_sighup: bool = False
    ) -> List[Process]:
        """Funció auxiliar per extreure processos, threads i kthreads.

        - include_priority: inclou el valor numèric de la prioritat.
        - filter_sighup: si és True, només retorna aquells que ignoren SIGHUP.
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
                status_file = os.path.join(proc_path, "status")

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

                if include_priority and len(after_comm) >= 16:
                    priority_val = int(after_comm[15])

                ignores_hup = self._is_sighup_ignored(status_file)

                # Comprovar si és Kernel Thread (kthread)
                if (flags & PF_KTHREAD) != 0:
                    if not filter_sighup or ignores_hup:
                        processes.append(
                            Process(
                                pid=int(pid),
                                command=command,
                                type=TaskType.KTHREAD,
                                priority=priority_val,
                            )
                        )
                    continue

                # Procés normal
                if not filter_sighup or ignores_hup:
                    processes.append(
                        Process(
                            pid=int(pid),
                            command=command,
                            type=TaskType.PROCESS,
                            priority=priority_val,
                        )
                    )

                # Threads secundaris
                task_folder = os.path.join(proc_path, "task")
                if os.path.exists(task_folder):
                    try:
                        tids = os.listdir(task_folder)
                    except (FileNotFoundError, PermissionError):
                        tids = []

                    for tid in tids:
                        if tid.isdigit() and tid != pid:
                            thread_stat_file = os.path.join(
                                task_folder, tid, "stat"
                            )
                            thread_comm_file = os.path.join(
                                task_folder, tid, "comm"
                            )
                            thread_status_file = os.path.join(
                                task_folder, tid, "status"
                            )

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

                            thread_ignores_hup = self._is_sighup_ignored(
                                thread_status_file
                            )
                            if not thread_ignores_hup:
                                # Si no té status propi al thread, comprovem el del procés pare
                                thread_ignores_hup = ignores_hup

                            if not filter_sighup or thread_ignores_hup:
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
        return self._parse_processes(include_priority=False, filter_sighup=False)

    def get_priorities(self) -> List[Process]:
        return self._parse_processes(include_priority=True, filter_sighup=False)

    def get_hup(self) -> List[Process]:
        return self._parse_processes(include_priority=True, filter_sighup=True)
