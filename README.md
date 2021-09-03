A skeleton language module for testing and demonstration purposes. Includes a loader and PCode injection module. You may choose to copy this code freely and use it as a basis for developing a language module.

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Building

This repository is designed to build as a Ghidra extension. To build:

- Install Gradle (this has been tested with Gradle 7.1, but should be widely compatible)
- Set the `GHIDRA_INSTALL_DIR` environment to the directory containing your Ghidra install
- Run `gradle buildExtension`
- The extension `.zip` file will appear in `dist` and can be imported into Ghidra.

## Skeleton Files

Skeleton files are identified by the magic bytes 8f eb fd a9 5e dd de 15; these were randomly chosen to avoid conflicts with other file formats.
