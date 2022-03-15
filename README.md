# MSTool

ModSecTool partially implements functionality of nxtool-ng for ModSecurity

## Installation

Copy script and configure mstool.json

## Usage

```bash
Options:
  -h, --help            show this help message and exit
  -a, --append          Automatically add new rules to the rule file
  -s SERVER, --server=SERVER
                        FQDN to which we should restrict operations.
  -t, --tag             Actually tag matching items in DB.
  -u URI, --uri=URI     Left part of relative URI
  -V, --verbose         Enable extended logging
  -w WL_FILE, --wlfile=WL_FILE
                        A path to whitelist file, will find matching events in
                        DB.
  -i UNIQUE_ID, --id=UNIQUE_ID
                        Find events by specific unique_id.
  -W, --warnoff         Enable extended logging
```


## License
[MIT](https://choosealicense.com/licenses/mit/)