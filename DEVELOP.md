# Сборка проекта

## Linux, macOS

В Github Actions сборка осуществляется путем вызова скриптов

```
.github/before-script.sh
.github/build-engine.sh
```

`.github/before-script.sh` устанавливает зависимости, клонирует и собирает openssl, собирает engine. Скрипты в `.github` используют переменные, заданные в `.github/config.sh`; они могут быть переопределены перемеными окружения.

### Вариант локальной сборки engine

*Действия выполняются из корня репозитория.*

Склонировать openssl в корень репозитория:

```
export OPENSSL_BRANCH=openssl-3.6.0
./.github/before-script/20-pull-openssl.sh
```

Собрать openssl:

```
export OPENSSL_INSTALL_PREFIX=$(pwd)/build/
./.github/before-script/30-build-openssl.sh
```

Собрать engine:

```
export OPENSSL_INSTALL_PREFIX=$(pwd)/build/
./.github/build-engine.sh
```

### Решение проблем

* В этом проекте есть submodules. Нужно позвать `git submodule update --init --recursive`.
* Для запуска тестов нужен perl.