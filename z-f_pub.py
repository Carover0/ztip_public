import os
import configparser
import telebot

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, "config.ini"))

DATA_DIR = config["ZINGO"]["DATA_DIR"]
TOKEN = config["BOT"]["BOT_TOKEN"]
TOKEN_PRUEBA = config["BOT"]["TOKEN_PRUEBA"]
CLAVE_ADD = config["AGREGAR"]["CLAVE"]
TRANS = config["DEPOSITOS"]["TRANS"]
BLINDADA = config["DEPOSITOS"]["BLINDADA"]

#bot = telebot.TeleBot(TOKEN_PRUEBA)
bot = telebot.TeleBot(TOKEN)

import threading
import tempfile
import time
import shlex
import paramiko
from telebot.types import Message
import json
import re
from datetime import datetime


############# usuarios autorizados - YO, tengo la llave maestra para que no me puedan borrar de mi bot
ALLOWED_USERS_FILE = os.path.join(BASE_DIR, "allowed_users.json")
MASTER_ADMIN = int(config["MASTER"]["ADMIN"])
DEFAULT_ALLOWED_USERS = {MASTER_ADMIN}

def load_allowed_users():
    if not os.path.exists(ALLOWED_USERS_FILE):
        return set(DEFAULT_ALLOWED_USERS)
    try:
        with open(ALLOWED_USERS_FILE, "r") as f:
            data = json.load(f)
            users = set(int(x) for x in data if str(x).isdigit())
            return users.union(DEFAULT_ALLOWED_USERS)  # siempre incluir master
    except Exception as e:
        print(f"[WARN] could not load {ALLOWED_USERS_FILE}: {e}")
        return set(DEFAULT_ALLOWED_USERS)


def save_allowed_users(users):
    with open(ALLOWED_USERS_FILE, "w") as f:
        json.dump(sorted(list(users)), f, indent=2)

# Funciones auxiliares
def console_access_denied(chat_id, uid):
    msg = (
        f"zebra@node:~$ whoami\n"
        f"user_{uid}\n"
        "zebra@node:~$ /add_user\n"
        "[SECURITY] Unauthorized access attempt detected.\n"
        "[ERROR] Access denied.\n"
        "zebra@node:~$ operation aborted.\n"
    )
    bot.send_message(chat_id, f"<pre>{msg}</pre>", parse_mode="HTML")

def console_usage(chat_id):
    msg = (
        "zebra@node:~$ [USAGE ERROR]\n"
        "--------------------------------------------------\n"
        "Usage: /add_user &lt;user_id&gt; &lt;key&gt;\n"
        "Example: /add_user 123456789 **********\n\n"
        "Adds a new authorized user to the bot’s whitelist."
    )
    bot.send_message(chat_id, f"<pre>{msg}</pre>", parse_mode="HTML")

def console_invalid_key(chat_id, uid):
    msg = (
        f"zebra@node:~$ whoami\n"
        f"user_{uid}\n"
        "zebra@node:~$ /add_user\n"
        "[SECURITY] Unauthorized access attempt detected.\n"
        "[ERROR] Invalid key provided.\n"
        "[ALERT] This action has been logged.\n"
        "[INFO] Make sure you have the correct key to add a user.\n"
        "zebra@node:~$ operation aborted.\n"
        "zebra@node:~$ exit\n"
    )
    bot.send_message(chat_id, f"<pre>{msg}</pre>", parse_mode="HTML")

def console_invalid_user_id(chat_id, uid):
    msg = (
        f"zebra@node:~$ whoami\n"
        f"user_{uid}\n"
        "zebra@node:~$ /add_user\n"
        "[SECURITY] Invalid user ID format detected.\n"
        "[ERROR] The provided user ID is not numeric.\n"
        "[INFO] Usage: /add_user &lt;user_id&gt; &lt;key&gt;\n"
        "zebra@node:~$ operation aborted.\n"
        "zebra@node:~$ exit\n"
    )
    bot.send_message(chat_id, f"<pre>{msg}</pre>", parse_mode="HTML")

def console_already_authorized(chat_id, uid, new_user_id):
    msg = (
        f"zebra@node:~$ whoami\n"
        f"user_{uid}\n"
        f"zebra@node:~$ /add_user {new_user_id}\n"
        "[INFO] The user is already authorized.\n"
        f"user_{new_user_id} has existing access rights.\n"
        "zebra@node:~$ operation aborted.\n"
        "zebra@node:~$"
    )
    bot.send_message(chat_id, f"<pre>{msg}</pre>", parse_mode="HTML")

def console_success(chat_id, uid, new_user_id):
    msg = (
        f"zebra@node:~$ whoami\n"
        f"user_{uid}\n"
        f"zebra@node:~$ /add_user {new_user_id}\n"
        "[SUCCESS] User added to authorized list.\n"
        f"user_{new_user_id} now has access rights.\n"
        "[INFO] Changes have been saved to allowed_users.json\n"
        "zebra@node:~$ operation completed.\n"
        "zebra@node:~$"
    )
    bot.send_message(chat_id, f"<pre>{msg}</pre>", parse_mode="HTML")

@bot.message_handler(commands=['add_user'])
def add_user(message: Message):
    sender_id = message.from_user.id
    ALLOWED_USERS = load_allowed_users()
    print(f"Loaded allowed users: {ALLOWED_USERS}, sender_id={sender_id}, type(sender_id)={type(sender_id)}")

    parts = message.text.strip().split()

    if sender_id not in ALLOWED_USERS:
        console_access_denied(message.chat.id, sender_id)
        return

    if len(parts) != 3:
        console_usage(message.chat.id)
        return

    new_user_str, key = parts[1], parts[2]

    if key != CLAVE_ADD:
        console_invalid_key(message.chat.id, sender_id)
        return

    try:
        new_user_id = int(new_user_str)
    except ValueError:
        console_invalid_user_id(message.chat.id, sender_id)
        return

    if new_user_id in ALLOWED_USERS:
        console_already_authorized(message.chat.id, sender_id, new_user_id)
        return

    ALLOWED_USERS.add(new_user_id)
    save_allowed_users(ALLOWED_USERS)
    console_success(message.chat.id, sender_id, new_user_id)

@bot.message_handler(commands=['remove_user'])
def remove_user(message: Message):
    sender_id = message.from_user.id
    ALLOWED_USERS = load_allowed_users()

    parts = message.text.strip().split()

    if sender_id not in ALLOWED_USERS:
        msg = (
            f"zebra@node:~$ whoami\n"
            f"user_{sender_id}\n"
            "zebra@node:~$ /remove_user\n"
            "[SECURITY] Unauthorized access attempt detected.\n"
            "[ERROR] Access denied.\n"
            "zebra@node:~$ operation aborted.\n"
        )
        bot.send_message(message.chat.id, f"<pre>{msg}</pre>", parse_mode="HTML")
        return

    if len(parts) != 2:
        msg = (
            "zebra@node:~$ [USAGE ERROR]\n"
            "--------------------------------------------------\n"
            "Usage: /remove_user <user_id>\n"
            "Example: /remove_user 123456789\n"
            "Removes a user from the authorized list.\n"
            "zebra@node:~$"
        )
        bot.send_message(message.chat.id, f"<pre>{msg}</pre>", parse_mode="HTML")
        return

    try:
        target_id = int(parts[1])
    except ValueError:
        msg = (
            f"zebra@node:~$ whoami\n"
            f"user_{sender_id}\n"
            "zebra@node:~$ /remove_user\n"
            "[ERROR] The provided user ID is not numeric.\n"
            "zebra@node:~$ operation aborted.\n"
        )
        bot.send_message(message.chat.id, f"<pre>{msg}</pre>", parse_mode="HTML")
        return

    if target_id not in ALLOWED_USERS:
        msg = (
            f"zebra@node:~$ whoami\n"
            f"user_{sender_id}\n"
            f"zebra@node:~$ /remove_user {target_id}\n"
            "[INFO] User is not in the authorized list.\n"
            "zebra@node:~$ operation aborted.\n"
        )
        bot.send_message(message.chat.id, f"<pre>{msg}</pre>", parse_mode="HTML")
        return

    if target_id == sender_id:
        msg = (
            f"zebra@node:~$ whoami\n"
            f"user_{sender_id}\n"
            f"zebra@node:~$ /remove_user {target_id}\n"
            "[ERROR] You cannot remove yourself from the authorized list.\n"
            "zebra@node:~$ operation aborted.\n"
        )
        bot.send_message(message.chat.id, f"<pre>{msg}</pre>", parse_mode="HTML")
        return

    ALLOWED_USERS.remove(target_id)
    save_allowed_users(ALLOWED_USERS)

    msg = (
        f"zebra@node:~$ whoami\n"
        f"user_{sender_id}\n"
        f"zebra@node:~$ /remove_user {target_id}\n"
        "[SUCCESS] User removed from authorized list.\n"
        f"user_{target_id} no longer has access rights.\n"
        "[INFO] Changes have been saved to allowed_users.json\n"
        "zebra@node:~$ operation completed.\n"
        "zebra@node:~$"
    )
    bot.send_message(message.chat.id, f"<pre>{msg}</pre>", parse_mode="HTML")

@bot.message_handler(commands=['list_users'])
def verid_json_handler(message: Message):
    sender_id = message.from_user.id
    ALLOWED_USERS = load_allowed_users()

    if sender_id not in ALLOWED_USERS:
        msg = (
            f"zebra@node:~$ whoami\n"
            f"user_{sender_id}\n"
            "zebra@node:~$ /verid_json\n"
            "[SECURITY] Unauthorized access attempt detected.\n"
            "[ERROR] Access denied.\n"
            "zebra@node:~$ operation aborted.\n"
        )
        bot.send_message(message.chat.id, f"<pre>{msg}</pre>", parse_mode="HTML")
        return
    
    try:
        if isinstance(ALLOWED_USERS, set):
            ALLOWED_LIST = list(ALLOWED_USERS)
        else:
            ALLOWED_LIST = ALLOWED_USERS

        json_content = json.dumps({"allowed_users": ALLOWED_LIST}, indent=4)
    except Exception as e:
        bot.send_message(
            message.chat.id,
            f"<pre>[ERROR] Could not load JSON: {e}</pre>",
            parse_mode="HTML"
        )
        return

    msg = (
        f"zebra@node:~$ whoami\n"
        f"user_{sender_id}\n"
        "zebra@node:~$ /verid_json\n"
        f"{json_content}\n"
        "zebra@node:~$ operation completed.\n"
        "zebra@node:~$"
    )
    bot.send_message(message.chat.id, f"<pre>{msg}</pre>", parse_mode="HTML")
    

#################################################################################################

import configparser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.ini")

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

SSH_HOST = config["SSH"]["HOST"]
SSH_USER = config["SSH"]["USER"]
SSH_PASSWORD = config["SSH"]["PASSWORD"]
LOG_PATH = os.path.expanduser(config["SSH"]["LOG_PATH"])  # Convierte "~" en ruta real

LIGHTWALLET_SERVER = config["ZCASH"]["LIGHTWALLET_SERVER"]
ZECWALLET_BINARY = config["ZCASH"]["ZECWALLET_BINARY"]
ZINGO_DATA_DIR = config["ZCASH"]["ZINGO_DATA_DIR"]
ZATS_PER_ZEC = int(config["ZCASH"]["ZATS_PER_ZEC"])

FILE_PATH = os.path.join(BASE_DIR, config["LOCAL"]["FILE_PATH"])

def connect_ssh():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(SSH_HOST, username=SSH_USER, password=SSH_PASSWORD, timeout=10)
    return ssh

def _quote_for_remote(args):
    return " ".join(shlex.quote(a) for a in args)

def run_remote_command(cmd_args, timeout=30):
    ssh = None
    try:
        ssh = connect_ssh()
    except Exception as e:
        return -10, "", f"[SSH CONNECT ERROR] {e}"

    try:
        remote_cmd = _quote_for_remote(cmd_args)
        stdin, stdout, stderr = ssh.exec_command(remote_cmd, timeout=timeout)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        try:
            rc = stdout.channel.recv_exit_status()
        except Exception:
            rc = 0
        return rc, out, err
    except Exception as e:
        return -11, "", f"[SSH EXEC ERROR] {e}"
    finally:
        try:
            if ssh:
                ssh.close()
        except:
            pass

# --- Helpers Telegram ---
def safe_log(log: str) -> str:
    log = log.strip()
    return log if len(log) < 4096 else log[-4096:]

def send_log(chat_id: int, log: str):
    try:
        formatted = f"<pre>{log}</pre>"
        bot.send_message(chat_id, formatted, parse_mode='HTML', disable_web_page_preview=True)
    except Exception as e:
        print("Error al enviar log:", e)

def build_zingo_cmd(cmd: str, extra_args=None):
    base = [ZECWALLET_BINARY, "--server", LIGHTWALLET_SERVER, "--data-dir", DATA_DIR, cmd]
    if extra_args:
        base.extend(extra_args)
    return base


# --- Handler /zec ---
SAFE_CMDS = {
    "balance": build_zingo_cmd("balance"),
    "info": build_zingo_cmd("info"),
    #"addresses": build_zingo_cmd("addresses"),
    "syncstatus": build_zingo_cmd("sync"),
    "height": build_zingo_cmd("height"),
    "transactions": build_zingo_cmd("transactions"),
    "lasttxid": build_zingo_cmd("transactions", ["--last", "1"]),
    "zecprice": build_zingo_cmd("current_price"),
    "quicksend": build_zingo_cmd("quicksend"),  
    "confirm": build_zingo_cmd("confirm"),  
    "sync": build_zingo_cmd("sync"),  
    #"t_addresses": build_zingo_cmd("t_addresses"),  
    "shield": build_zingo_cmd("shield"),  
    "current_price": build_zingo_cmd("current_price"),  
    "sends_to_address": build_zingo_cmd("sends_to_address"),
}

def sanitize_html(text: str) -> str:
    allowed_tags = ['b','i','u','s','code','pre','a']
    def repl(m):
        tag = m.group(1).lower()
        if tag in allowed_tags:
            if m.group(0).startswith('</'):
                return f"</{tag}>"
            else:
                return f"<{tag}>"
        return ""
    text = re.sub(r"</?([^ >]+)[^>]*>", repl, text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text

def extract_json_from_output(text: str):
    m = re.search(r"\{", text)
    if not m: return None
    start = m.start()
    try:
        return json.loads(text[start:])
    except Exception:
        last = text.rfind("}")
        if last != -1:
            try:
                return json.loads(text[start:last+1])
            except Exception:
                return None
    return None

def zats_to_zec(zats):
    try:
        return float(zats) / ZATS_PER_ZEC
    except Exception:
        return 0.0

def mask_address(addr: str, head=8, tail=6):
    if not addr or len(addr) <= head + tail + 3:
        return addr
    return addr[:head] + "..." + addr[-tail:]

def run_remote_command(cmd_args, timeout=30):
    ssh = None
    try:
        ssh = connect_ssh()
        remote_cmd = _quote_for_remote(cmd_args)
        stdin, stdout, stderr = ssh.exec_command(remote_cmd, timeout=timeout)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err
    except Exception as e:
        return -11, "", f"[SSH EXEC ERROR] {e}"
    finally:
        if ssh:
            ssh.close()

# ---------------- Handler /zec ----------------
XSAFE_CMDS = ["balance", "info", "addresses", "transactions", "lasttxid", "zecprice", "confirm", "quicksend", "sync", "t_addresses", "shield"]
import json

@bot.message_handler(commands=['zec'])
def cmd_zec(message: Message):
    chat_id = message.chat.id
    uid = message.from_user.id
    
    if uid not in load_allowed_users():
        bot.send_message(
            chat_id,
            "<pre>"
            "zebra@node:~$ whoami\n"
            f"user_{uid}\n"
            f"zebra@node:~$ {message.text}\n"
            "[SECURITY] Unauthorized command attempt detected.\n"
            "[SECURITY] Logging incident...\n"
            "[ERROR] Permission denied.\n"
            "[ALERT] This action has been recorded in the system audit.\n"
            "zebra@node:~$ operation aborted.\n"
            "zebra@node:~$ exit\n"
            "</pre>",
            parse_mode="HTML"
        )

        return


    try:
        parts = shlex.split(message.text.strip())
    except ValueError:
        bot.send_message(
            chat_id,
            "<pre>"
            "zebra@node:~$ " + message.text + "\n"
            "bash: syntax error: malformed command\n"
            "[ERROR] Command could not be parsed.\n"
            "[INFO] Please check command syntax and try again.\n"
            "zebra@node:~$ operation aborted.\n"
            "</pre>",
            parse_mode="HTML"
        )

        return

    if len(parts) < 2:
        bot.send_message(
            chat_id,
            "<pre>"
            "zebra@node:~$ [USAGE]\n"
            "--------------------------------------\n"
            "Usage: /zec &lt;command&gt;\n"
            "\n"
            "Commands:\n"
            "  /zec balance       # Show current wallet balance\n"
            "  /zec transactions  # List last 5 transactions\n"
            "  /zec quicksend     # Send ZEC (usage: /zec quicksend &lt;address&gt; &lt;amount&gt; [memo])\n"
            "  /zec shield        # Shield transparent funds to Orchard\n"
            "\n"
            "Admin:\n"
            "  /add_user <user_id> <key>   # Authorize user\n"
            "  /remove_user <user_id>      # Authorized users only can remove\n"
            "----------------------------------------\n"
            "zebra@node:~$"
            "</pre>",
            parse_mode="HTML"
        )


        return

    subcmd = parts[1].lower()
    if subcmd not in SAFE_CMDS:
        bot.send_message(
           chat_id,
           "<pre>"
           "zebra@node:~$ " + message.text + "\n"
           "[SECURITY] Command not allowed.\n"
           "[ERROR] Permission denied.\n"
           "[INFO] Check available commands using /zec\n"
           "zebra@node:~$ operation aborted.\n"
           "</pre>",
           parse_mode="HTML"
        )
        return

    bot.send_message(
        chat_id,
        f"<pre>"
        "zebra@node:~$ whoami\n"
        f"user_{uid}\n"
        f"zebra@node:~$ {subcmd}\n"
        "[INFO] Executing remote command...\n"
        "[INFO] Please wait while the operation completes.\n"
        "zebra@node:~$</pre>",
        parse_mode="HTML"
    )


    def worker():
        raw_output = ""
        text = ""
        try:
            # Comando remoto
            cmd_args = [
                ZECWALLET_BINARY,
                "--server", LIGHTWALLET_SERVER,
                "--data-dir", ZINGO_DATA_DIR,
                subcmd
            ]
            rc, out, err = run_remote_command(cmd_args)
            raw_output = out or err or ""

            if subcmd == "balance":
                info = parse_zingo_balance(raw_output)
                text = format_balance_dashboard(info)

            elif subcmd == "transactions":
                txlist = parse_zingo_transactions(raw_output)
                text = format_txlist_dashboard(txlist)

            elif subcmd == "addresses":
                text = parse_zingo_addresses(raw_output)
            elif subcmd == "t_addresses":
                text = parse_zingo_taddresses(raw_output)
            elif subcmd == "sends_to_address":
                text = parse_zingo_sends_to_address(raw_output)    
            elif subcmd == "quicksend":
                if len(parts) < 4:
                    bot.send_message(
                        chat_id,
                        "<pre>"
                        "zebra@node:~$ [USAGE]\n"
                        "------------------------------------\n"
                        "Usage: /zec send &lt;address&gt; &lt;amount_in_zats&gt; [optional memo]\n"
                        "\n"
                        "Example:\n"
                        "  /zec send t1XyzAbC123 1000000 Donation for faucet\n"
                        "\n"
                        "[INFO] Make sure the address is valid and amount is numeric (in zats).\n"
                        "zebra@node:~$"
                        "</pre>",
                        parse_mode="HTML"
                    )
                    return
                dest_addr = parts[2]
                if not parts[3].isdigit():
                    bot.send_message(
                        chat_id,
                        "<pre>"
                        "zebra@node:~$ /zec quicksend\n"
                        "[ERROR] The amount must be numeric (in zats).\n"
                        "[INFO] Example: /zec quicksend t1XyzAbC123 1000000 Optional memo\n"
                        "zebra@node:~$ operation aborted.\n"
                        "</pre>",
                        parse_mode="HTML"
                    )
                    return
                amount_zats = int(parts[3])
                memo = " ".join(parts[4:]) if len(parts) > 4 else ""
                zec_send(chat_id, dest_addr, amount_zats, memo)
                return  

            elif subcmd == "shield":
                zec_shield(chat_id)
                return  

            else:
                text = "<pre>" + sanitize_html(raw_output) + "</pre>"
                if err:
                    text += "\n\nSTDERR:\n" + sanitize_html(err)

        except Exception as e:
            text = f"[ERROR] {e}\nSalida cruda:\n{sanitize_html(raw_output)}"

        if text.strip():
            if len(text) > 3500:
                with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8", suffix=".txt") as tf:
                    tf.write(text)
                    tmpname = tf.name
                with open(tmpname, "rb") as fh:
                    bot.send_document(chat_id, fh, caption="zebra@node:~$ [INFO] output (file)")
                os.remove(tmpname)
            else:
                bot.send_message(chat_id, text, parse_mode="HTML", disable_web_page_preview=True)
        else:
            bot.send_message(chat_id, "⚠️ No se obtuvo salida del comando.")

    threading.Thread(target=worker, daemon=True).start()

############# shield

def zec_shield(chat_id: int):
    try:
        text = "zebra@node:~$ quickshield\n"
        text += "[INFO] Shielding transparent funds to Orchard...\n"
        msg = bot.send_message(chat_id, f"<pre>{text}</pre>", parse_mode="HTML")

        quick_cmd = [
            ZECWALLET_BINARY,
            "--server", LIGHTWALLET_SERVER,
            "--data-dir", ZINGO_DATA_DIR,
            "quickshield"
        ]
        rc, out, err = run_remote_command(quick_cmd, timeout=60)
        output_text = out or err or ""

        text += "zebra@node:~$ [INFO] Connecting to lightwalletd...\n"
        text += "zebra@node:~$ [INFO] Broadcasting transaction...\n"
        text += "zebra@node:~$ [INFO] Processing response...\n\n"
        if rc == 0 and (
            "Broadcasting transaction" in output_text
            or "Transaction sent" in output_text
            or '"txids"' in output_text
        ):
            text += "[OK] Transparent funds successfully shielded to Orchard.\n"
            text += "zebra@node:~$ [INFO] Run '/zec balance' to verify changes.\n"
        else:
            text += "[ERROR] Shielding operation failed or returned unexpected output.\n"
            text += f"{sanitize_html(output_text)}\n"

        bot.edit_message_text(
            chat_id=chat_id,
            message_id=msg.message_id,
            text=f"<pre>{text}</pre>",
            parse_mode="HTML",
            disable_web_page_preview=True
        )

    except Exception as e:
        err_msg = f"zebra@node:~$ [ERROR] {str(e)}"
        bot.send_message(chat_id, f"<pre>{err_msg}</pre>", parse_mode="HTML")

############ send

def zec_send(chat_id: int, dest_addr: str, amount_zats: int, memo: str = ""):
    amount_zec = zats_to_zec(amount_zats)

    text_lines = [
        "------------ SEND ==> ------------",
        f"To     : {dest_addr}",
        f"Amount : {amount_zec:.8f} ZEC",
        f"Memo   : {memo or '(sin memo)'}",
        "Status : Sending transaction...",
        "Fee    : will be deducted automatically"
    ]
    text = "<pre>" + "\n".join(text_lines) + "</pre>"
    msg = bot.send_message(chat_id, text, parse_mode="HTML", disable_web_page_preview=True)

    quick_cmd = [
        ZECWALLET_BINARY,
        "--server", LIGHTWALLET_SERVER,
        "--data-dir", ZINGO_DATA_DIR,
        "quicksend",
        dest_addr,
        str(amount_zats)
    ]
    if memo:
        quick_cmd.append(memo)

    rc, out, err = run_remote_command(quick_cmd, timeout=60)

    if rc == 0 and out and ("Broadcasting transaction" in out or "Transaction sent" in out):
        text_lines.append("\n[OK] Transaction sent successfully.\nCheck /zec transactions once it’s mined.")
    else:
        text_lines.append(f"\n[=>] Sending...\n<pre>{sanitize_html(out or err)}</pre>zebra@node:~$ [OK] operation complete.")
    bot.edit_message_text(chat_id=chat_id, message_id=msg.message_id,
                          text="<pre>" + "\n".join(text_lines) + "</pre>",
                          parse_mode="HTML", disable_web_page_preview=True)


#### formato

def parse_zingo_balance(raw_text: str) -> dict:
    info = {
        "uabalance": 0,
        "zbalance": 0,
        "tbalance": 0,
        "ua_addresses": [],
        "z_addresses": [],
        "t_addresses": []
    }

    lines = raw_text.splitlines()
    for line in lines:
        line = line.strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip().replace("_","")
        try:
            val_int = int(val)
        except:
            val_int = 0

        if key == "total_orchard_balance":
            info["uabalance"] = val_int
        elif key == "total_sapling_balance":
            info["zbalance"] = val_int
        elif key == "total_transparent_balance":
            info["tbalance"] = val_int

    return info

def format_balance_dashboard(info: dict, spendable: int = 0) -> str:
    total_ua = zats_to_zec(info.get("uabalance", 0))
    total_z = zats_to_zec(info.get("zbalance", 0))
    total_t = zats_to_zec(info.get("tbalance", 0))
    total_all = total_ua + total_z + total_t

    # Spendable = Unified + Shielded
    total_spendable = total_ua + total_z

    lines = []
    lines.append("------------ ZEC BALANCE ------------")
    lines.append("")
    lines.append("Unified balance     : {:>12.8f} ZEC".format(total_ua))
    lines.append("Shielded balance    : {:>12.8f} ZEC".format(total_z))
    lines.append("Transparent balance : {:>12.8f} ZEC".format(total_t))
    lines.append("")
    lines.append("Spendable total     : {:>12.8f} ZEC ★".format(total_spendable))
    lines.append("-----------------------------------------")
    lines.append("TOTAL BALANCE       : {:>12.8f} ZEC".format(total_all))
    lines.append("-----------------------------------------")
    lines.append("")
    lines.append("zebra@node:~$ [INFO] Balance fetched successfully.")
    lines.append("[OK] Operation completed.")


    def add_addresses(title, addrs, balance_key=None):
        if not addrs:
            return
        lines.append(f"{title}:")
        for a in addrs:
            addr = mask_address(a if isinstance(a, str) else a.get("address",""))
            bal = zats_to_zec(a.get(balance_key,0)) if balance_key and not isinstance(a,str) else None
            if bal is not None:
                lines.append(f"  {addr:<24} {bal:>12.8f} ZEC")
            else:
                lines.append(f"  {addr}")
        lines.append("")

    add_addresses("Unified Addresses", info.get("ua_addresses", []), "balance")
    add_addresses("Transparent Addresses", info.get("t_addresses", []), "balance")
    add_addresses("Shielded Addresses", info.get("z_addresses", []), "balance")

    return "<pre>" + "\n".join(lines) + "</pre>"


############ list

def parse_zingo_transactions(raw_text: str):
    txs = []
    blocks = re.findall(r"\{(.*?)\}", raw_text, re.DOTALL)
    for b in blocks:
        tx = {}
        for field in ["txid", "datetime", "kind", "value", "fee", "status", "blockheight"]:
            m = re.search(rf"{field}\s*:\s*(.+)", b)
            if m:
                val = m.group(1).strip()
                if field in ["value", "fee", "blockheight"]:
                    try:
                        val = int(val)
                    except:
                        val = 0
                tx[field] = val
        if tx:
            txs.append(tx)
    return txs


def format_txlist_dashboard(txlist: list) -> str:
    filtered = [tx for tx in txlist if tx.get("txid")]
    
    filtered.sort(key=lambda x: x.get("blockheight", 0), reverse=True)
    
    latest = filtered[:5]

    if not latest:
        return "<pre>No hay transacciones registradas.</pre>"

    lines = ["------------ TX HISTORY ------------\n"]
    for tx in latest:
        amount = tx.get("value", 0) / 1e8
        ts_raw = tx.get("datetime", "PENDING")
        txid = tx.get("txid", "PENDING")
        direction = "RECEIVED ← " if tx.get("kind", "received") == "received" else "SENT → "

        lines.append(f"{direction:<8} {amount:>12.8f} ZEC")
        lines.append(f"TXID: {txid}")
        lines.append(f"Date: {ts_raw}")
        lines.append("-"*36)
    lines.append("\nzebra@node:~$ [INFO] last 5 transactions loaded successfully [OK]")
    lines.append("zebra@node:~$")
    return "<pre>" + "\n".join(lines) + "</pre>"


########### direcciones
def parse_zingo_addresses(raw_output: str) -> str:
    addresses = re.findall(r'"encoded_address"\s*:\s*"([^"]+)"', raw_output)

    if not addresses:
        return "<pre>No se encontraron direcciones.</pre>"
    
    lines = [
    "------------ RECEIVE SHIELDED -------------",
    "→ ZEC only!",
    "→ [INFO] Only Zcash is accepted",
    "→ [TIP] Your contributions keep the bot running",
    ""
]

    for i, addr in enumerate(addresses, 1):
        lines.append(f"{addr}")

    return "<pre>" + "\n".join(lines) + "</pre>"


def parse_zingo_taddresses(raw_output: str) -> str:
    taddresses = re.findall(r'"encoded_address"\s*:\s*"([^"]+)"', raw_output)

    if not taddresses:
        return "<pre>No se encontraron direcciones transparentes.</pre>"

    lines = [
    "------------ RECEIVE TRANSPARENT -------------",
    "→ ZEC only!",
    "→ [INFO] Only Zcash is accepted",
    "→ [TIP] Your contributions keep the bot running",
    ""
]

    for i, addr in enumerate(taddresses, 1):
        lines.append(f"{addr}")

    return "<pre>" + "\n".join(lines) + "</pre>"

############### comandos

def zec_help_commands(message) -> str:
    user_id = message.from_user.id
    command = message.text  

    lines = [
        "zebra@node:~$ cat /etc/zebra/commands.list",
        f"zebra@node:~$ [INFO] user_{user_id}",
        "",
        "----------- PUBLIC COMMANDS -----------",
        "/deposit       : receive funds",
        "/about         : show system & bot info",
        "",
        "----------- WHITE LIST COMMANDS --------",
        "/zec quicksend        : send ZEC to with memo",
        "/zec balance          : show wallet balances",
        "/zec transactions     : list last 5 transactions",
        "/zec shield           : shield transparent funds",
        "/zec sends_to_address : counts sent outputs per address",
        "",
        "----------- ADMIN COMMANDS -------------",
        "/add_user <id> <key>  : authorize new user",
        "/remove_user <id>     : remove an authorized user",
        "/list_users           : list all authorized users",
        "",
        "zebra@node:~$ awaiting input...",
        "",
    ]

    full_text = "\n".join(lines)
    full_text = full_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    return f"<pre>{full_text}</pre>"


@bot.message_handler(commands=['comandos','commands'])
def send_help(message):
    bot.send_message(message.chat.id, zec_help_commands(message), parse_mode="HTML")

############################ conteo de depositos

def parse_zingo_sends_to_address(raw_output: str) -> str:
    match = re.search(r'{.*}', raw_output, re.DOTALL)
    if not match:
        return "<pre>zebra@node:~$ [ERROR] No JSON found</pre>"

    try:
        data = json.loads(match.group(0))
    except Exception:
        return "<pre>zebra@node:~$ [ERROR] Invalid JSON</pre>"

    if not data:
        return "<pre>zebra@node:~$ [INFO] No addresses found</pre>"

    sorted_items = sorted(data.items(), key=lambda x: x[1], reverse=True)

    def shorten(addr: str) -> str:
        if len(addr) <= 40:
            return addr
        return addr[:20] + "..." + addr[-40:]

    lines = [
        "---------- SENDS TO ADDRESSES ----------",
        "",
        "zebra@node:~$ [INFO] Detected recipients",
        "zebra@node:~$ [INFO] Format: address = count",
        "",
    ]

    for addr, amount in sorted_items:
        lines.append(f"{shorten(addr)} = {amount}")

    lines.append("")
    lines.append("-----------------------------------------")
    lines.append("zebra@node:~$ [INFO] Parsed successfully [OK]")


    return "<pre>" + "\n".join(lines) + "</pre>"

###############################################################################

def zec_info_live():
    try:
        quick_cmd = [
            ZECWALLET_BINARY,
            "--server", LIGHTWALLET_SERVER,
            "--data-dir", ZINGO_DATA_DIR,
            "info"
        ]

        rc, out, err = run_remote_command(quick_cmd, timeout=60)
        output_text = out or err or ""

        json_data = extract_json_from_output(output_text)
        return json_data

    except Exception:
        return None


@bot.message_handler(commands=['about'])
def about(message: Message):
    sdata = zec_info_live()

    msg = (
        "<pre>"
        "zebra@node:~$ whoami\n"
        f"zebra@node:~$ whoami user_{message.from_user.id}\n"
        "zebra@node:~$ cat /etc/zebra/about\n"
        "------------------------------------------------------------\n"
        "ZTip - Zcash Node CLI Interface\n"
        "------------------------------------------------------------\n"
        "A lightweight remote shell for interacting with Zcash node\n"
        "operations (Zebra / Lightwalletd / Zingo-CLI).\n"
        "\n"
        "Developed by:  cΔrovΣr0\n"
        "zebra@node:~$ [LINK] https://carover0.github.io/pagina/\n"
        "zebra@node:~$ [LINK] https://free2z.cash/cΔrovΣr0\n"
        "------------------------------------------------------------\n"
        "zebra@node:~$ [INFO]\n"
        f"{json.dumps(sdata, indent=2)}\n"
        "------------------------------------------------------------\n"
        "Visit --> https://t.me/zcashespchat  (to learn about Zcash)\n\n"
        "zebra@node:~$ donate [INFO] dev_address:\n"
        "u1s7dkgz3qutt5g5wn7c7wl8z6gf5fvhset06arxgy8tgr9pqs0cqvngxdglr69f2grmp3ewms34dw5lm98qn7a3esa72apw26jpdydt5k7dek04pgckj6a90nuzql80lzdg2kpk564nxzjalj0t690ghk28lxkv0edrn3dt9w4kn6fke8kjhuqewqtzvw6jdanfms6r6hd56x5dz3gz7\n"
        "\n"
        "zebra@node:~$ [INFO] service ready\n"
        "</pre>"
    )

    bot.send_message(message.chat.id, msg, parse_mode="HTML")


###################### depositos


@bot.message_handler(commands=['deposit'])
def show_deposit(message):
    text = f"""<pre>
zebra@node:~$ cat /etc/zebra/deposit_addresses.caro    
zebra@node:~$ [INFO] Deposit addresses
zebra@node:~$ [TIP] Try /zec balance to check your wallet
--------------------------------------------
--> TRANSPARENT ADDRESS:
{TRANS}

--> UNIFIED ADDRESS:
{BLINDADA}
--------------------------------------------
zebra@node:~$ [NOTE] For easy copy on mobile:
zebra@node:~$ [CMD] /t_address → transparent only
zebra@node:~$ [CMD] /u_address → unified only
--------------------------------------------
zebra@node:~$ [OK] Ready to receive deposits 
</pre>"""

    bot.send_message(message.chat.id, text, parse_mode="HTML")

@bot.message_handler(commands=['t_address'])
def show_deposit(message):
    text = f"""<pre>
{TRANS}
</pre>"""

    bot.send_message(message.chat.id, text, parse_mode="HTML")


@bot.message_handler(commands=['u_address'])
def show_deposit(message):
    text = f"""<pre>
{BLINDADA}
</pre>"""

    bot.send_message(message.chat.id, text, parse_mode="HTML")


################################################################################

# FIN sincro

def zec_sync_bot():
    while True:
        try:
            rc, out, err = run_remote_command([ZECWALLET_BINARY, "--server", LIGHTWALLET_SERVER,
                                               "--data-dir", ZINGO_DATA_DIR, "sync", "status"])
            output_text = out or err or ""
            m = re.search(r'"percentage_total_outputs_scanned"\s*:\s*([\d.]+)', output_text)
            if m:
                pct = float(m.group(1))
                if pct < 100:
                    print(f"[ZEC SYNC] Bloques pendientes ({pct:.2f}%), ejecutando sync run...")
                    run_remote_command([ZECWALLET_BINARY, "--server", LIGHTWALLET_SERVER,
                                        "--data-dir", ZINGO_DATA_DIR, "sync", "run"])
                else:
                    print("[ZEC SYNC] Todo al día, no se ejecuta sync.")
            else:
                 print("[ZEC SYNC] No se pudo detectar el porcentaje, ignorando...")
        except Exception as e:
            print("[ZEC SYNC] Error:", e)

        time.sleep(1800)

threading.Thread(target=zec_sync_bot, daemon=True).start()

############################


if __name__ == "__main__":
    print("\n💛 Ztip Bot 💛\n\niniciado y esperando comandos...")

    while True:
        try:
            bot.polling(non_stop=True, timeout=60) 
        except Exception as e:
            print(f"[ERROR] Bot polling falló: {e}")
            time.sleep(15)  
