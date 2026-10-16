# Запуск Frida Gadget внутри APK

Для этого клиента подготовлена автономная схема:

```text
Открытие приложения
    -> GameApp вызывает System.loadLibrary("back")
    -> загружается libback.so
    -> Gadget читает libback.config.so
    -> Gadget загружает libback.script.so и вызывает init("early", parameters)
    -> загрузчик скачивает /v1/script, проверяет и исполняет source
    -> вызывается init("remote") скачанного агента
    -> Gadget продолжает запуск приложения
```

Загрузчик возвращает Promise из `rpc.exports.init()`, поэтому Gadget дожидается
завершения загрузки и проверки. При ошибке запрос завершается сообщением в логах,
агент не исполняется, и запуск приложения продолжается. Повторный вызов init
возвращает прежний результат, не скачивая и не исполняя агент второй раз.

## Какие файлы лежат в APK

```text
lib/arm64-v8a/
  libback.so
  libback.config.so
  libback.script.so
```

| Файл | Содержание |
| --- | --- |
| libback.so | Настоящая ELF-библиотека официального Frida Gadget 17.23.3 для Android arm64 |
| libback.config.so | Обычный текст JSON с настройками Gadget |
| libback.script.so | Текстовый Frida ESM bundle с загрузчиком, криптографией и мостами Java/ObjC |

Имена текстовых файлов начинаются с lib и заканчиваются .so, чтобы Android
извлекал их рядом с native-библиотекой. Gadget поддерживает конфиг с таким
именем и относительный путь к скрипту.
[Документация Gadget](https://frida.re/docs/gadget/).

В твоём исходном libback.so конфигурация и bootstrap вшиты и обфусцированы.
Подготовленный вариант использует официальный Gadget с внешними конфигом и
bundle. Старую libback.so заменяет новая библиотека с тем же именем. Вызов
System.loadLibrary("back") уже найден в GameApp из classes2.dex, его менять
для этой распаковки не требуется.

## Конфигурация

Файл libback.config.so:

```json
{
  "runtime": "qjs",
  "code_signing": "optional",
  "interaction": {
    "type": "script",
    "path": "libback.script.so",
    "on_change": "ignore",
    "parameters": {
      "execute": true
    }
  }
}
```

`type: script` включает автономное исполнение. `path` разрешается относительно
библиотеки Gadget. `execute: true` включает запуск полученного агента;
`execute: false` оставляет только загрузку и проверки. Параметр читается при
первом вызове init. Для изменения параметра в подготовленном APK поменяй его
в apk-libs/arm64-v8a/libback.config.so и заново упакуй APK.

## Сборка загрузчика и подготовка Gadget

Команды выполняются из /home/justflyne/projects/sc-studio:

```sh
python3 frida-loader/build.py
```

Эта команда собирает loader.bundle.js из loader.js и уже имеющихся зависимостей.
Если папка apk-libs существует, обновляется и libback.script.so внутри неё.
JavaScript остаётся скриптом: для него собирается Frida bundle. Native Gadget
берётся готовым из официального релиза, сборка C/C++ для этого варианта не нужна.

Первая подготовка трёх файлов либо восстановление официальной библиотеки:

```sh
python3 frida-loader/prepare_gadget.py
```

Результат — frida-loader/apk-libs/arm64-v8a/. Скрипт скачивает официальный
Android arm64 Gadget, сверяет опубликованный SHA-256 архива, распаковывает .xz,
проверяет архитектуру ELF и сохраняет библиотеку под именем libback.so.
Источник и контрольные суммы записаны в apk-libs/gadget-info.json.
[Официальный релиз 17.23.3](https://github.com/frida/frida/releases/tag/17.23.3).

## Упаковка именно твоего APK

Предоставленная папка — обычная распаковка ZIP: AndroidManifest.xml уже в
бинарном виде, классы уже в DEX, ресурсы уже скомпилированы. pack_apk.py копирует
их в новый APK, заменяет libback.so и добавляет два текстовых файла рядом.
Старая JAR-подпись исключается, остальная META-INF сохраняется. Исходная папка
только читается. Проверено, что extractNativeLibs=true и INTERNET уже присутствуют.

```sh
python3 frida-loader/pack_apk.py \
  /home/justflyne/projects/backtobrawl_59.1210_fastdl \
  frida-loader/output/backtobrawl-gadget-unsigned.apk
```

Для этого helper нужны исходные бинарные файлы APK. Проект после apktool d
с текстовым манифестом и smali сначала собирается через apktool b; pack_apk.py
распознаёт неподходящий текстовый манифест и выдаёт ошибку.

Для другого APK потребуется его собственный ранний вызов загрузки библиотеки,
например в Java-коде:

```java
System.loadLibrary("back");
```

Он должен выполняться в нужном процессе. Также нужны ABI arm64-v8a, разрешение
INTERNET и extractNativeLibs=true для этой схемы с внешними файлами в lib/.
Скачанный игровой агент использует offsets конкретной игровой библиотеки v59.

## Выравнивание, подпись и установка

Упаковщик создаёт **unsigned APK**. Для установки используются Android SDK
Build Tools (zipalign, apksigner), Java для apksigner и adb для подключения
телефона. Эти инструменты в текущем окружении не найдены, поэтому подпись и
установка здесь не выполнялись.

Сначала выравнивание, затем подпись своим keystore:

```sh
zipalign -P 16 -f 4 \
  frida-loader/output/backtobrawl-gadget-unsigned.apk \
  frida-loader/output/backtobrawl-gadget-aligned.apk

apksigner sign \
  --ks /путь/к/your-key.jks \
  --out frida-loader/output/backtobrawl-gadget.apk \
  frida-loader/output/backtobrawl-gadget-aligned.apk

apksigner verify --verbose frida-loader/output/backtobrawl-gadget.apk
```

Пароль keystore вводится по запросу apksigner. Если своего ключа ещё нет,
keytool из JDK позволяет создать локальный тестовый ключ:

```sh
keytool -genkeypair -keystore frida-loader/local-test.jks \
  -alias local-test -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Local APK Test"
```

Тогда передай local-test.jks в --ks. Обновление уже установленного пакета
требует совместимого сертификата подписи; новый тестовый ключ отличается от
исходной подписи приложения.

После успешной подписи, если сертификат подходит для установленного пакета:

```sh
adb install -r frida-loader/output/backtobrawl-gadget.apk
```

Дальше открываешь приложение обычным способом: Gadget и загрузчик запускаются
внутри его процесса. Сообщения ищи в logcat по строкам [loader] и [agent].
Сеть телефона должна иметь доступ к script.backtobs.xyz:8787.

Порядок выравнивания и подписи:
[zipalign](https://developer.android.com/tools/zipalign),
[apksigner](https://developer.android.com/tools/apksigner).

## Что проверено

Официальный Android Gadget проверен по SHA-256 релизного архива и архитектуре
ELF. Автономный режим настоящего официального Gadget 17.23.3 проверен на Linux:
он читает относительный script path, вызывает init(early), ждёт запуска
безвредного подписанного тестового агента и лишь затем возвращает управление
приложению. Агент инициализируется один раз. При неверной подписи приложение
продолжает запуск без агента. Отчёт — gadget-verification.json.

Установка и работа игровых native hooks на Android-устройстве здесь не
проверялись. Расшифрование ответов настоящего сервера проверялось в предыдущем
этапе; алгоритм проверки ответа при адаптации к Gadget сохранён.
