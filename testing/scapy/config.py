#!/usr/bin/env python3

import subprocess
import os


def copy(src_path, dst_path, username):
    print(f"copying {src_path} to {dst_path}...", end=" ")

    # replace any ~ with /home/{username}
    dst_path = dst_path.replace('~', f"~{username}")
    subprocess.run(["cp", src_path, os.path.expanduser(dst_path)],
                   user=f"{username}")
    print("done")


def rsync(src_path, dst_path, hostname, username):
    print(f"copying {src_path} to {hostname}:{dst_path}...", end=" ")
    subprocess.run(["rsync", f"{src_path}", f"{hostname}:{dst_path}"],
                   user=f"{username}", env={"HOME": f"/home/{username}"})
    print("done")
