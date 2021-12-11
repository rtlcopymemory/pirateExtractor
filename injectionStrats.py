import os

from utils import get_eval_code, inject, execute_node, src_dir


def old_obfuscated(src_dir: str, root_dir: str, payload: str):
    js_path = src_dir + os.listdir(root_dir + src_dir)[0]
    main_path = root_dir + js_path

    eval_code = get_eval_code(main_path)
    print(f"Eval code: {eval_code}")
    inject(main_path, payload.format(eval_code), 0)

    webhook = execute_node(root_dir, js_path)
    print(f"Webhook: {webhook}")


def new_obfuscated(src_dir: str, root_dir: str):
    js_path = src_dir + os.listdir(root_dir + src_dir)[0]
    main_path = root_dir + js_path
    inject(main_path, ";console.log(superstarlmao);process.exit(0);", 1)

    webhook = execute_node(root_dir, js_path)
    print(f"Webhook: {webhook}")


def get_strategy(files: dict, root_dir: str, kind: int, payload: str) -> callable:
    ret = None

    if kind == 0:
        def func():
            old_obfuscated(src_dir, root_dir, payload)
        ret = func
    elif kind == 1:
        def func():
            new_obfuscated("builds/", root_dir)
        ret = func

    return ret
