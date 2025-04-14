#!/usr/bin/env python3

import subprocess
import os


def copy(src_path, dst_path):
    print(f"loading config {os.path.basename(src_path)}...", end="")

    subprocess.run(["cp", src_path, os.path.expanduser(dst_path)])
    print("done")


def rsync(src_path, dst_path, hostname, username):
    print(f"copying {src_path} to {hostname}:{dst_path}...", end=" ")
    subprocess.run(
        ["rsync", f"{src_path}", f"{hostname}:{dst_path}"],
        user=f"{username}",
        env={"HOME": f"/home/{username}"},
    )
    print("done")
