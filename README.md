## **ZTip Bot → Minimal Zcash CLI Tipper**

> [!TIP]
>📺 [video](https://free2z.cash/uploadz/public/c%CE%94rov%CE%A3r0/ztip2.mp4)

ZTip Bot is a Telegram bot inspired by the Zcash terminal, designed to interact with nodes and execute commands remotely while maintaining a clean and secure console-style interface.
It allows users to receive and send ZEC, check balances, transactions, and addresses, as well as perform basic administrative commands.

## **Technical Features**

ZTip is fully developed in Python, ensuring portability and ease of maintenance.
The bot establishes a secure SSH connection using the Paramiko library, enabling direct command execution on the remote Zcash node, whether Zebra, Lightwalletd, or Zingo-CLI with controlled authentication and detailed logging.

The entire user experience is inspired by the aesthetics of a real terminal, replicating the authentic Zcash console environment.
Its design is deliberately minimalist, no graphical elements or buttons, prioritizing simplicity, text readability, and the feeling of operating a node directly from the command line.

At its core, the bot adheres to cypherpunk principles: transparency, decentralization, and direct user control over node interaction.
Every command can be traced, reproduced, and manually verified, maintaining a 1:1 correspondence with real Zcash operations.

## **Project Structure**

> [!NOTE]
> These are the only files the bot requires to operate.  
> The structure remains minimal to preserve simplicity and transparency.
```
ztip_bot/  
│  
├── z-f.py                # Main bot file  
├── allowed_users.json    # List of authorized users  
└── bot.pid               # Active process PID  
```

## **Available Commands**
#### **Main Commands**

```bash
| Command               | Description                                                   |
|---------------------- | --------------------------------------------------------------|
| /deposit              | Displays unified and transparent addresses to receive ZEC.    |
| /zec balance          | Checks the full balance (unified, shielded, transparent).     |
| /zec transactions     | Lists recent transactions with amount, type, and TXID.        |
| /zec quicksend        | Sends ZEC to an address with an optional memo.                |
| /zec shield           | Shields transparent funds by moving them to the Orchard pool. |
| /zec sends_to_address | counts sent outputs per address.                              |
```
Each response includes detailed information, a block-style structure, and the final operation status.
The user experiences the process as if they were operating a Zcash node in real time synchronization, saving, and CLI output.

#### **Administrative Commands**

```bash
| Command                   | Function                                                  |
| ------------------------- | --------------------------------------------------------- |
| /add_user <user_id> <key> | Authorizes a new user in the local whitelist.             |
| /remove_user <user_id>    | Revokes access for an existing user.                      |
| /about                    | Displays system information, version, and active backend. |
```
These commands are only available to users registered in allowed_users.json,
ensuring that critical operations (such as sending or authorizing users) cannot be executed without permission.

#### **Main Menu View**

```bash
zebra@node:~$ cat /etc/zebra/commands.list
zebra@node:~$ [INFO] user_2138507839

----------- PUBLIC COMMANDS -----------
/deposit       : receive funds
/about         : show system & bot info

----------- WHITE LIST COMMANDS --------
/zec quicksend        : send ZEC with memo (optional)
/zec balance          : show wallet balances
/zec transactions     : list last 5 transactions
/zec shield           : shield transparent funds
/zec sends_to_address : counts sent outputs per address

----------- ADMIN COMMANDS -------------
/add_user <id> <key>  : authorize new user
/remove_user <id>     : remove an authorized user
/list_users           : list all authorized users

zebra@node:~$ awaiting input...
```

#### **Public Command /deposit**

> [!TIP]
> Use `/t_address` or `/u_address` for quick mobile copy/paste of deposit addresses.

```bash

zebra@node:~$ cat /etc/zebra/deposit_addresses.caro    
zebra@node:~$ [INFO] Deposit addresses
zebra@node:~$ [TIP] Try /zec balance to check your wallet
--------------------------------------------
--> TRANSPARENT ADDRESS:
t1JYg6zmRwosC2U13Nvnerx8HsBX4YmTVxt

--> UNIFIED ADDRESS:
u1kragrthrjfzpyyp3h4mxe079ed0r8xzqdulf2xnlev2d6238p8y2eq9y72tg46s9m9hz2ll5c7n8eqwa786ma2jqqcly660jqgydwavg
--------------------------------------------
zebra@node:~$ [NOTE] For easy copy on mobile:
zebra@node:~$ [CMD] /t_address → transparent only
zebra@node:~$ [CMD] /u_address → unified only
--------------------------------------------
zebra@node:~$ [OK] Ready to receive deposits
```
The user receives both addresses (t and u) to make deposits either transparently or through the unified address.

#### **Command /zec balance**
```bash
------------ ZEC BALANCE ------------

Unified balance     :   0.00355033 ZEC
Shielded balance    :   0.00000000 ZEC
Transparent balance :   0.00000000 ZEC

Spendable total     :   0.00355033 ZEC ★
-----------------------------------------
TOTAL BALANCE       :   0.00355033 ZEC
-----------------------------------------

zebra@node:~$ [INFO] Balance fetched successfully.
[OK] Operation completed.

```

#### **Transaction History (/zec transactions)**

```bash
------------ TX HISTORY ------------

SENT →     0.00106191 ZEC
TXID: 3c736c7323f7b4e6e83041730549edfa292f158dcdc0187ae65869cadd222f98
Date: 2025-11-02 23:16:23 UTC
------------------------------------
SENT →     0.00007000 ZEC
TXID: 0e1758df4ebab063881f99fcee884c63eed0045e661fc5ab24d579aa0972a20f
Date: 2025-11-02 23:05:06 UTC
------------------------------------
RECEIVED ←    0.00121191 ZEC
TXID: bc02251e37f63593df22e2479845c2569413c5bddd0c330e4e9035a0e6936f5f
Date: 2025-11-02 22:39:10 UTC
------------------------------------
SENT →     0.00005000 ZEC
TXID: b3e1a5b4ef423ae36ab1e8c9849df28617e8d753b46aeb463c8c026f37f8ad32
Date: 2025-11-02 15:25:01 UTC
------------------------------------
SENT →     0.00005000 ZEC
TXID: 25ebd875841016dd927e6b3092564d361b7b49b548924148e69bde54b8d48f8c
Date: 2025-11-02 15:20:32 UTC
------------------------------------

zebra@node:~$ [INFO] last 5 transactions loaded successfully [OK]
zebra@node:~$
```
#### **Command /zec quicksend**

> [!CAUTION]
> The bot executes **real transactions** on your Zingo wallet.  
> Always double-check amounts and addresses before sending.

Quickly sends ZEC to an address with an optional memo:
```bash
------------ SEND ==> ------------
To     : u1s7dkgz3qutt5g5wn7c7wl8z6gf5fvhset06arxgy8tgr9pqs0cqvngxdglr69f2grmp3ewms34dw5lm98qn7a3esa72apw26jpdydt5k7dek04pgckj6a90nuzql80lzdg2kpk564nxzjalj0t690ghk28lxkv0edrn3dt9w4kn6fke8kjhuqewqtzvw6jdanfms6r6hd56x5dz3gz7
Amount : 0.00007000 ZEC
Memo   : Prueba desde Ztip
Status : Sending transaction...
Fee    : will be deducted automatically

[=>] Sending...
Launching sync task...
Launching save task...
{
  "txids": [
    "0e1758df4ebab063881f99fcee884c63eed0045e661fc5ab24d579aa0972a20f"
  ]
}
Save task shutdown successfully.
Zingo CLI quit successfully.
zebra@node:~$ [OK] operation complete.
```
#### **Command /zec shield**

> [!CAUTION]
> The bot executes **real transactions** on your Zingo wallet.  
> Always double-check amounts and addresses before sending.

Protects transparent funds by moving them to the unified address:

```bash
zebra@node:~$ quickshield
[INFO] Shielding transparent funds to Orchard...
[INFO] Connecting to lightwalletd...
[INFO] Broadcasting transaction...
[INFO] Processing response...

[OK] Transparent funds successfully shielded to Orchard.
zebra@node:~$ [INFO] Run '/zec balance' to verify changes.

```

#### **Command /about**

> [!NOTE]
> All system information shown in `/about` is pulled directly from your Lightwalletd server and node.

Displays information about the system and the bot:

```bash
zebra@node:~$ whoami
zebra@node:~$ whoami user_2138507839
zebra@node:~$ cat /etc/zebra/about
------------------------------------------------------------
ZTip - Zcash Node CLI Interface
------------------------------------------------------------
A lightweight remote shell for interacting with Zcash node
operations (Zebra / Lightwalletd / Zingo-CLI).

Developed by:  cΔrovΣr0
zebra@node:~$ [LINK] https://carover0.github.io/pagina/
zebra@node:~$ [LINK] https://free2z.cash/cΔrovΣr0
------------------------------------------------------------
zebra@node:~$ [INFO]
{
  "version": "v0.0.0.0-dev",
  "git_commit": "",
  "server_uri": "https://carover0.xyz:9067/",
  "vendor": "ECC LightWalletD",
  "taddr_support": true,
  "chain_name": "main",
  "sapling_activation_height": 419200,
  "consensus_branch_id": "c8e71055",
  "latest_block_height": 3121328
}
------------------------------------------------------------
Visit --> https://t.me/zcashespchat  (to learn about Zcash)

zebra@node:~$ donate [INFO] dev_address:
u1s7dkgz3qutt5g5wn7c7wl8z6gf5fvhset06arxgy8tgr9pqs0cqvngxdglr69f2grmp3ewms34dw5lm98qn7a3esa72apw26jpdydt5k7dek04pgckj6a90nuzql80lzdg2kpk564nxzjalj0t690ghk28lxkv0edrn3dt9w4kn6fke8kjhuqewqtzvw6jdanfms6r6hd56x5dz3gz7

zebra@node:~$ [INFO] service ready
```

## **Project Philosophy**

ZTip is a human–interface experiment for Zcash, designed to reproduce the aesthetics, flow, and logic of a real node within a Telegram chat.
Its purpose is to offer a purely textual experience no graphical interfaces, browsers, or external dependencies—bringing users closer to direct interaction with the network.

The project prioritizes privacy, verifiable transparency, and decentralization, while maintaining simplicity and full user control over every operation.
ZTip aims to demonstrate that secure, private, and functional communication with a Zcash node can be achieved purely through text—without sacrificing autonomy or aesthetics.

#### **Technical Notes**

All commands are audited and reproducible on a full Zebra node.

It is recommended to use an authorized user to execute critical commands (quicksend, shield).

The bot output preserves the Zcash console aesthetics, using tags such as [INFO], [OK], [TIP].


## **Try ZTip Bot**

ZTip Bot is live and available for testing in the following channel:

👉 https://t.me/zcashespchat

Anyone can use the public commands such as /commands, /deposit, or /about.
Sensitive commands require prior authorization (whitelist).

---

# **Install**

## Requirements (Before Installing)

> [!IMPORTANT]
> ZTip **cannot run** without the full Zcash stack: **Zebra + Lightwalletd + Zingo-CLI**.  
> Make sure all three are installed, running, and reachable.

> [!CAUTION]
> If `zingo-cli` or `lightwalletd` are misconfigured, the bot may send incorrect balances or fail transactions.


## How to Create the Configuration INI File

> [!WARNING]
> Never share your `config.ini`. It contains passwords, node access, and your Telegram bot token.

> [!NOTE]
> The bot reads `config.ini` on every startup. Any change requires restarting the bot.


To run the bot, you need to create a configuration file named config.ini. This file tells the bot how to connect to your node, Telegram, and manage Zcash settings. Follow the template below and fill in your own information. Do not share this file publicly if it contains sensitive data.

```
[SSH]
# Your SSH node host (e.g., 123.45.67.89)
HOST = 
# SSH username
USER = 
# SSH password
PASSWORD = 
# Path to the Zebra log file
LOG_PATH = ~/zeb_logs/zebrad_live.log

[ZCASH]
# Lightwallet server URL (e.g., https://lightwallet.example:9067)
LIGHTWALLET_SERVER = 
# Path to zingo-cli binary
ZECWALLET_BINARY = 
# Zingo data directory
ZINGO_DATA_DIR = 
# Number of zats per ZEC (usually 100000000)
ZATS_PER_ZEC = 100000000

[LOCAL]
# Path to the local file used by the bot
FILE_PATH = 

[BOT]
# Telegram bot token for the main bot
BOT_TOKEN = 
# Optional: Telegram bot token for testing
TOKEN_PRUEBA = 

[AGREGAR]
# Optional: Key for adding features or users
CLAVE = 

[MASTER]
# Telegram user ID of the admin
ADMIN = 

[ZINGO]
# Zingo data directory (can be the same as ZINGO_DATA_DIR above)
DATA_DIR = 

[DEPOSITOS]
# Blind deposit address
BLINDADA = 
# Transparent deposit address
TRANS = 
```

Save this template as config.ini.
- Replace each field with your own values:
- SSH: information for connecting to your node.
- ZCASH: your zingo-cli paths and lightwallet server.
- BOT: Telegram bot tokens.
- DEPOSITOS: your Zcash deposit addresses.
- Keep the file safe, especially the tokens, passwords, and keys.
- Run the bot with this config.ini in the same directory.

## **Steps to Clone the Repository**
```
# 1. Open a terminal on your machine or server
# 2. (Optional) change to the folder where you want to keep the bot
cd /path/to/your/bots

# 3. Clone the repo
git clone https://github.com/Carover0/ztip_public.git

# 4. Change into the directory
cd ztip_public

# 5. (Optional) View latest commits or switch branch
git log --oneline
# E.g., if there’s a specific version tag:
# git checkout <tag_or_branch>

# 6. Install dependencies (assuming Python & pip are used)
#Make sure Python 3.10+ is installed. Then, install required packages:
pip install -r requirements.txt

# 7. Create or edit your config.ini according to the template
# (fill in your node’s SSH, Zcash settings, bot token, etc.)

# 8. Run the bot
python3 z‑f.py   # or whichever file is the main script
```
## **Authorized Users File**

> [!WARNING]
> Anyone listed in `allowed_users.json` can trigger sensitive wallet commands.  
> Only add users you fully trust.

The bot automatically creates allowed_users.json on first run if it doesn’t exist. You can pre-fill it with your admin ID:
```
[
  123456789
]
```

With this, anyone cloning your repo can:

- Install dependencies.
- Configure config.ini.
- Run the bot.

Have admin access immediately if their Telegram ID is in allowed_users.json.

---

## Final Notes / Tips

> [!TIP]
> Keep your bot in a separate low-privilege user account on the server.

> [!NOTE]
> Every command executed by ZTip can be verified manually through Zebra or Zingo-CLI.


1. Security First
- Keep config.ini and allowed_users.json private. They contain sensitive credentials and access keys.  
- Never share your bot token or SSH password publicly.  
2. Node Compatibility  
- The bot is tested with Zebra, Lightwalletd, and Zingo-CLI. Other implementations may work but are not guaranteed.
3. Auditable Operations
- Every command replicates a real Zcash node operation. You can verify transactions manually via your node.
4. Minimalist Design Philosophy
- ZTip is intentionally text-based to reproduce the CLI experience. No graphical interface, no browser dependencies.
5. Contributing
- Pull requests are welcome. Make sure any code preserves the terminal-style aesthetic and secure operation flow.
6. Support / Community
- Join the testing and discussion channel: [ZCash ESP Chat](https://t.me/zcashespchat)
- Visit: [ZcashEsp](https://zcashesp.com/)


########################################################  
> [!TIP]
> Thanks for trying ZTip! Your feedback helps strengthen the Zcash ecosystem.

