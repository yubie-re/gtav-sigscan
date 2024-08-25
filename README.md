## gtav-sigscan

Emulates Rockstar's sig scanning/anticheat system in GTA 5. You can use this to test certain files (unpacked/dumps) to determine if they will flag the anticheat while injected.
Tested on the 3179 game build.
## Usage
```
  sigscan [OPTION...]

  -h, --help             Show help message
  -s, --savejson <file>  Serialize signatures to a JSON file
  -l, --loadjson <file>  Load signatures from a JSON file
  -f, --file <file>      Loads a specific file to test
  -d, --dir <directory>  Loads a specific directory to test (default: ./files/)
  -z, --silent           No output
  -v, --verbose          Prints all signature data
```
## Authors

👤 **yubie**

* Github: [@yubie-re](https://github.com/yubie-re)

👤 **brunph**

* Github: [@brunph](https://github.com/brunph)