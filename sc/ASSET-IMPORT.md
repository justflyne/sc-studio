# Новые ресурсы UI

Все пять PNG добавлены в `ui.sc`; изображения находятся в новом атласе внутри
`ui_tex.sc`. Исходные PNG сохраняются без изменения пикселей и прозрачности.
Размер на экране задан геометрией SC по образцу существующих ресурсов.

| Исходный PNG | Экспорт в SC | ID клипа | Размер геометрии |
| --- | --- | ---: | --- |
| `emblem_icon_09.png` | `icon_skins_developers` | 209 | 79,6 × 85,5 |
| `player_icon_creator_3_26.png` | `player_icon_creator_3_26` | 203 | 100 × 100 |
| `player_icon_creator_4_26.png` | `player_icon_creator_4_26` | 175 | 100 × 100 |
| `emoji_creator_3_26.png` | `emoji_creator_3_26` | 168 | 55,3 × 54,5 |
| `emoji_creator_4_26.png` | `emoji_creator_4_26` | 142 | 59,8 × 54,5 |

Это однокадровые клипы. Emoji сохраняют структуру существующих статичных emoji:
пустое текстовое поле и изображение. Две иконки игрока имеют размер и начало
координат по образцу `player_icon_00`; значок коллекции — по образцу
`icon_skins_*`. Превью находятся в `asset-previews/`.

## Где используются `icon_skins_*`

В исходном `ui.sc` найдено 26 клипов с такими экспортами. Ни один из них не
используется как дочерний ресурс другого клипа. Полный список и соответствия
коллекциям из таблиц проверенного APK записаны в `icon-skins-usage.csv`.

В `/home/justflyne/projects/backtobrawl_59.1210_fastdl/assets/csv_logic/skin_campaigns.csv`
поле `CampaignIconExportName` содержит имя экспорта значка. Например:

| Коллекция (`Name`) | `CampaignIconExportName` |
| --- | --- |
| `SC_MAKE` | `icon_skins_make` |
| `BRAWLYWOOD` | `icon_skins_brawlywood` |
| `GOLD` | `icon_skins_gold` |
| `SILVER` | `icon_skins_silver` |
| `RANKED` | `icon_skins_ranked` |

Связь конкретного скина с коллекцией задаётся полем `Campaigns` в `skins.csv`.
Для dev-коллекции нужно указать `icon_skins_developers` в
`CampaignIconExportName` её строки, а нужным dev-скинам назначить имя этой
коллекции в `Campaigns`. Набор dev-скинов здесь не назначался.

## Подключение новых иконок и emoji в игре

Добавление экспорта в SC создаёт графический ресурс. Для новых доступных в игре
элементов нужны строки в соответствующих таблицах клиента:

| Таблица | `IconSWF` | `IconExportName` |
| --- | --- | --- |
| `player_thumbnails.csv` | `sc/ui.sc` | `player_icon_creator_3_26` |
| `player_thumbnails.csv` | `sc/ui.sc` | `player_icon_creator_4_26` |
| `emotes.csv` | `sc/ui.sc` | `emoji_creator_3_26` |
| `emotes.csv` | `sc/ui.sc` | `emoji_creator_4_26` |

В проверенном APK существующие иконки и emoji ссылаются на отдельные
`sc/player_icons.sc` и `sc/emoji.sc`. Новые ресурсы этой задачи добавлены именно
в `ui.sc`, поэтому для них выше указан этот путь. При переносе ресурсов в
отдельные SC нужно изменить `IconSWF` соответственно. Имена записей, настройки
доступности и выдачу следует согласовать с таблицами и сервером конкретного
клиента. Файлы APK этой задачей не изменялись.

В APK заменяй **оба** файла: `ui.sc` и `ui_tex.sc`. В SC Studio открывай обычный
`ui.sc`: текстуры подхватятся из соседнего `ui_tex.sc`.

Резервные копии находятся в `backups/creator-assets-20261014-215120/`:
`disk-before/` содержит исходные файлы с диска, `live-before/` — документ с
сохранёнными пользовательскими правками перед добавлением ресурсов.
Результаты проверки записаны в `asset-import-report.json`.
