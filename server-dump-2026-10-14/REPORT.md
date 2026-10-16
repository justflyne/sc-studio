# Дамп выдаваемого клиенту скрипта

Сервер: http://script.backtobs.xyz:8787. Дата: 14 октября 2026 года.
Клиент: /home/justflyne/projects/backtobrawl_59.1210_fastdl.
APK: пакет com.stealdev.btb, версия 59.1210, versionCode 591210.

Из libback.so восстановлены конфигурация Gadget и полный встроенный bootstrap:
**684 337 байт**, **28 модулей**. Обычным запросом протокола v3 скачан полный
скрипт для этого APK: **70 619 байт**, версия **ad602661a16ad0b8**, epoch **5**.
Проверены crypto_box, cnonce, Ed25519-подпись и SHA-256 исходного скрипта:

```text
ad602661a16ad0b8251b63186ee314d6269259e9500d1bd6ea89fb75a031aa76
```

Это снимок текущего выдаваемого скрипта и загрузчика APK. Серверный Python-код,
база, журналы, другие релизы и исчерпывающий перечень маршрутов не получены.
Скачанный JavaScript не исполнялся; исходные файлы APK не изменялись.
Временные закрытые ключи наших запросов не сохранялись на диск.

| Файл | Содержимое |
| --- | --- |
| PROTOCOL.md | Разбор полей, криптографии, кэша и адресов |
| v1-script/full/agent.bundle.js | Полные исходные байты скрипта; подпись и хеш относятся к ним |
| v1-script/full/agent.readable.js | Форматированная копия для чтения; её хеш отличается |
| v1-script/full/envelope.json | Расшифрованный полный ответ с source |
| v1-script/full/summary.json | Версия, размеры и результаты проверки |
| v1-script/unchanged/envelope.json | Расшифрованный ответ not_modified=true |
| v1-script/captured-response.json | Предоставленный пользователем перехват |
| v1-script/replayed-response.body | Ответ на точное повторение исходного запроса |
| client-analysis/modules/src/bootstrap.js | Восстановленный загрузчик APK |
| client-analysis/modules/src/remote/RemoteConfig.js | Конфигурация и открытые ключи |
| client-analysis/gadget-config.json | Конфигурация встроенного скрипта Frida |
| client-analysis/inputs.json | Контрольные суммы исходных файлов APK |
| client-analysis/AndroidManifest.decoded.xml | Декодированный манифест |
| fetch_script.py | Повторная загрузка и проверка без исполнения скрипта |
| extract_client.py | Повторное извлечение bootstrap из этой libback.so |
| manifest.json | Перечень проверочных запросов и результаты обмена v3 |

Повторить загрузку из корня проекта SC Studio (зависимость — PyNaCl):

```sh
.venv/bin/python server-dump-2026-10-14/fetch_script.py \
  --output server-dump-2026-10-14/v1-script/new-download
```

Проверить имеющуюся версию:

```sh
.venv/bin/python server-dump-2026-10-14/fetch_script.py \
  --have ad602661a16ad0b8 --have-epoch 5 \
  --output server-dump-2026-10-14/v1-script/new-cache-check
```

Сервер может обновиться: при устаревшем have второй запрос вернёт новый source.
Утилита сохраняет данные и не запускает агент.

Извлечение bootstrap требует pyelftools и cryptography:

```sh
.venv/bin/python server-dump-2026-10-14/extract_client.py \
  /home/justflyne/projects/backtobrawl_59.1210_fastdl/lib/arm64-v8a/libback.so \
  --output /tmp/btb-client-extracted
```

Первичные GET на /, /openapi.json, /docs, /api, /health, /scripts, /manifest.json,
/index.json, /scripts.json вернули 404; OPTIONS / вернул 501. Это проверочные
адреса, не маршруты из клиента. Тела и заголовки сохранены. 404 относится только
к конкретному запросу. Заголовок Server сообщает BTBScriptServer/2 Python/3.14.4.
