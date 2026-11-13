# ARC Raiders — handoff для ESP / Aim / Trigger / Minimap / menu-ui

## 1. Целевая задача

Нужен рабочий инструмент для ARC Raiders со следующими функциями:

- ESP: игроки, имена, дистанция, health, box/skeleton — после восстановления соответствующих полей;
- Minimap/Radar: координаты локального игрока, других actors и camera/yaw;
- Aim: world-to-screen, выбор цели, кости/точка прицеливания, калиброванная чувствительность;
- Trigger: активация только при валидном наведении на противника;
- Menu UI: ImGui, Insert для меню, клавиши функций, настройки overlay.

Сейчас **ни одна из этих runtime-функций не реализована и не проверена**. Нет actor list, координат, camera, team/health или world-to-screen.

Предпочтительная архитектура после получения offsets: external reader + transparent ImGui overlay. Internal DLL потребуется только для hooks/direct engine calls. Стандартная usermode инъекция на текущей системе не сработала: `VirtualAllocEx` error `5` до `LoadLibraryW`. Архитектура пока НЕ решена: `OpenProcess`/чтение живого процесса отдельно не проверялись, старый `README-RUN.md` показывает, что решает именно `rights: ReadProcessMemory(private regions) N of 5`, а не код `OpenProcess`. Это измеряется командой `arc_tool probe <pid>` (шаг 0–1 раздела 10).

## 2. Точная идентичность build

```text
Executable:          PioneerGame.exe
Product:             pioneer_2.03.x-CL-1450810
Engine file version: 5.7.4.0
Architecture:        x64
Preferred base:      0x140000000
Image size:          0x139F9000
EXE size:            322041712 bytes
PE timestamp:        0x6AEB721B
```

EXE:

```text
D:\tools\steamapps\common\Arc Raiders\PioneerGame\Binaries\Win64\PioneerGame.exe
```

Все значения ниже относятся только к `CL-1450810`. Heap VA меняются между запусками.

## 3. Главные артефакты

### Полный gameplay dump, создан в матче

```text
C:\Users\Malin\AppData\Local\Temp\PioneerGame (3).DMP
```

### Предыдущий gameplay dump

```text
C:\Users\Malin\AppData\Local\Temp\PioneerGame (2).DMP
Size: 10681401676 bytes
```

### USMAP

Пользователь предоставил `1450810.usmap` в архиве `1450810_[unknowncheats.me]_.zip`.

```text
Size:    5435248 bytes
SHA-256: 313d29e66a93e96e98d65353416e1df90bff31638daa4fd3ce3a8a50fb228f26
Format:  uncompressed USMAP v4
Names:   113898
Enums:   3755
Structs: 29100
Ext:     CEXT / PPTH / ENVP
```

USMAP parser проверен. **Schema/property indices — ordinals, не runtime byte offsets.** Не использовать их как offsets для ESP.

### Не разобранные артефакты в Dropbox (найдены 2026-11-13)

```text
/Dumper7-ARC-Raiders.zip        1,504,996 bytes  rev 66015caf1db934b309220
/1450810_[unknowncheats.me]_.zip 1,488,164 bytes  rev 66016a43183064b309220
/PioneerGame.exe                322,041,712 bytes  rev 66006382facb84b309220
/ARC-riders/README-RUN.md        15,149 bytes  (старый тул, см. ниже)
/ARC-riders/config.json             591 bytes
/ARC-riders/arc_riders_tool.exe 1,513,472 bytes  sha256 9df28ac9243130ea514fc22127a28e9bd0321806ea96a636b18357227e124623
/ARC-riders/ARC-riders-0.1-nondma.zip 651,154 bytes
```

`Dumper7-ARC-Raiders.zip` распакован пользователем 2026-11-13 в `/Dumper7-ARC-Raiders/` и прочитан.
Это НЕ вывод дампера и не SDK: это пакет запуска внутри процесса —

```text
/Dumper7-ARC-Raiders/arc_inject.exe    956,412 → 956,416 bytes   OpenProcess+VirtualAllocEx+CreateRemoteThread(LoadLibraryW)
/Dumper7-ARC-Raiders/Dumper-7.dll     2,995,200 bytes             сам даumper, имя менять нельзя
/Dumper7-ARC-Raiders/Dumper-7.ini           119 bytes             SDKGenerationPath=C:/Dumper-7, LogFilePath=C:/Dumper-7/dumper7.log, ShouldAutoUnload=1
/Dumper7-ARC-Raiders/README.txt             798 bytes             7 шагов: главный меню → админ PS → New-Item C:\Dumper-7 → arc_inject.exe <pid> <dll>
```

То есть вопрос «как устроен FName» он не закрывает сам по себе, но закрывает его запуск: Dumper-7 читает
пул средствами движка и пишет `Names.txt`/`Offsets` уже с расшифрованными именами, а `dumper7.log`
показывает, нашёл ли он `GNames`/`GObjects` в этом CL. `arc_inject.exe` — это `src/Injector.cpp` этого
репозитория; старый прогон падал на `VirtualAllocEx` error 5, при текущих выданных правах путь открыт
(проверено `probe`: VM_WRITE/CREATE_THREAD/SUSPEND_RESUME выданы, SeDebugPrivilege включён). Побайтовой
совместимости с локальной пересборкой нет: zip-файл и `out/arc_inject.exe` (956,416,
sha256 `2d9274c0ddec95dd6e87c402d1d4603559bf1b9bc4857f1cbea31b2f6eb4945c`) — один и тот же исходник,
разные сборки. Из песочницы zip не открыть: исходящая сеть разрешена только для github/npm/pypi, `curl`
на `*.dl.dropboxusercontent.com` падает с `SSL_ERROR_SYSCALL`. Текстовые файлы коннектор отдаёт в
`/home/user/ARC-riders/dropbox/` — там уже лежат `README.txt` и `Dumper-7.ini`.

Старый `ARC-riders-0.1-nondma` (2026-11-11) — внешний читалка-оверлей на D3D11 с уже написанным
порядком диагностики: аттач, матрица прав (`rights: ReadProcessMemory(private regions) N of 5`),
получение базы образа из PEB в обход Toolhelp, и поиск сессии F8 сканированием читаемой приватной
памяти с валидацией цепочки `GameInstance → LocalPlayers → PlayerController → Pawn → RootComponent →
RelativeLocation` независимой проверкой `ControlRotation`. Оффсеты там из «SDK dump 2025-11-04
(pre-1.0)», то есть для 2.03.x потенциально устаревшие; ESP в том туле упирался ровно в
`UWorld::PersistentLevel` через зашифрованный GWorld. Идея «валидировать цепочку согласованностью двух
независимых векторов, а не именем класса» для нашего маршрута интересна: она не требует `GNames` вообще.

### Репозиторий

```text
src/DumpFile.*     MDMP reads, chain scan, RTTI experiment, GObjects scans, FNamePool predicate
src/Main.cpp       CLI
src/Usmap.*        USMAP parser
src/ArcDecrypt.*   build-specific viewport candidate; не подтверждён
src/Chain.*        pointer-chain logic
src/Process.*      live process access, на игре заблокирован
tests/CoreTests.cpp
STATUS_RU.md       предыдущая подробная история
```

## 4. Самый сильный подтверждённый runtime-результат

Публичная цепочка независимо найдена structural chain scan и повторно проверена на двух gameplay dumps:

```text
Global RVA: 0x108FEEC0
Global VA:  0x1508FEEC0
Chain:      [[[[0x1508FEEC0] + 0xA0] + 0x250] + 0x160]
```

### Dump `(3)`, матч

```text
Object 1: 0x1390F2500
Object 2: 0x296F04ED0  = Object1 + 0xA0
Object 3: 0x296A6A6F0  = Object2 + 0x250
Object 4: 0x7F9D55C0   = Object3 + 0x160
```

### Dump `(2)`

```text
Object 1: 0x1DBCF5730
Object 2: 0x2A0498890
Object 3: 0x2A0548A70
Object 4: 0x1F53F1D00
```

### Стабильные vtables в обоих запусках

```text
Object 1 vtable: 0x14E03B0B0  — предположительно LocalPlayer, НЕ доказано
Object 2 vtable: 0x14E2802E0  — предположительно PlayerController, НЕ доказано
Object 3 vtable: 0x14D65BE30  — intermediate manager, класс неизвестен
Object 4 vtable: 0x14D8952A0  — предположительно UWorld, НЕ доказано
```

Дополнительные back-references в dump `(2)`:

```text
Object 3 + 0x158 = Object 2
Object 3 + 0x160 = Object 4
```

Цепочка полезна как стабильный entry point, но **не давать объектам окончательные UE class names до class validation**.

## 5. Что блокирует ESP сейчас

Стандартные UObject header поля не читаются как обычный UE layout:

```text
Object + 0x00 = in-image vtable
Object + 0x10 = 0
Object + 0x18 = 0
```

Поэтому обычные `ClassPrivate`, `NamePrivate`, `OuterPrivate` resolver не работает. Алгоритм защиты/перестановки полей неизвестен. Не выдумывать XOR masks: они не восстановлены.

Не восстановлены:

- FNamePool/GNames;
- GUObjectArray;
- class/name resolution;
- подтверждённый UWorld;
- PersistentLevel/Levels/Actors;
- Actor RootComponent и coordinates;
- PlayerCameraManager/CameraCachePrivate/POV;
- health/team/bones;
- GameViewportClient.

## 6. FName и доступ — итог 2026-11-13 (четвёртый прогон)

Инъекция закрыта как измеренный факт про игру:

```text
se_debug_privilege=enabled
error: VirtualAllocEx failed ... : Win32 error 5
```

Хэндл с восемью правами выдан, `SeDebugPrivilege` включён (строка это подтверждает), `ReadProcessMemory`
работает 5 из 5 — а `VirtualAllocEx` всё равно `ERROR_ACCESS_DENIED`. То есть защита фильтрует именно
удалённую аллокацию, а не «нет прав». Практический вывод зафиксирован: **Dumper-7 внутрь этого процесса не
засунуть**, и любой internal-вариант (hook, ImGui inside, engine W2S) тоже. Архитектура одна: внешний
читалка + собственное окно-оверлей, Aim/Trigger через ввод, всё остальное — офлайн-разбор дампа.

Инструмент перестроен под это, а не под надежду:
- `arc_inject` сначала зовёт `ntdll!NtAllocateVirtualMemory` и только потом `VirtualAllocEx`, и печатает
  `nt_allocate_virtual_memory=status=0x...`, а при отказе обоих — текст, который прямо говорит, что путь
  закрыт и дальше только external. Это последний тест на «отхукован ли только Win32-враппер»;
- `arc_tool probe-write <pid>`: та же аллокация + `VirtualProtectEx` с тем же `protect` (сеантический
  no-op для игры). Специально **не** пишет в чужую память: при отказе аллокации это уже ничего не решает,
  а риск сессии добавляет. `writeprocessmemory` тестируется только на собственной только что зарезервированной
  странице;
- у меня в прошлый раз `probe` вообще не выполнился: `$p` был пуст, и в `probe.txt` попал блок usage —
  теперь при нехватке аргумента печатается `error: "probe" needs a PID. In PowerShell: $p=(Get-Process
  PioneerGame).Id` с кодом 2, чтобы файл отчёта нельзя было принять за результат; elevated-строка сама
  считает `$p` внутри команды.

Блокатор по именам классов всё ещё не закрыт, и причина теперь точная: **команды по дампам не были
выполнены** (в вставке нет ни `fname3b.txt`, ни `fname2.txt`), а не «инструмент ничего не нашёл».
`dump-fname-blocks` с шестью маркерами по `(3)` и тот же прогон по `(2)` с якорем `0xA6A00000` — вот что
решает, и игре для этого не нужно быть запущенной. Из `(3)` у нас только то, что маркерные области
оказались алиас-таблицей `[0x03][A][NUL][B][NUL][lower(A)][NUL]`, а `0xA6A00000` там — 64 нулевых байта
(адрес heap из другой сессии, переносить его между дампами нельзя).

### 6.1 Восьмой прогон: обрыв цепочки объяснён, и это не кодек

Якорь `0xa6f10000`, `block_size=0x10000`, sweep по всем страницам. Факты:

```text
block[2] data=0xa6f10000 entries=536 first="None" last="IPv6"
  stop=+25d4 bytes=616c4d73 0601 "IPv4" 6001 "IPv6" 0000 0000 ...
  resync=none-before-window-end
page sweep: 21 chain-validated block(s), total_names>=2390
PREDICATE PASS blocks=21 names=2390 pool_referrers_image=0 heap=1
```

`pool_names.txt` (1978 строк) показал главное: первые 536 ординаров — это настоящие `EName` движка в
каноническом порядке (`0 None`, `1 ByteProperty`, ... `304 LogHttp`, `534 IPv4`, `535 IPv6`), то есть блок
найден правильно, база правильная, кодек правильный. Остальные 1442 строки — мусор: 20 «блоков» sweep'а
это исполняемый код/rodata, где цепочка из 60–90 односимвольных «имён» случайно удовлетворяет правилу
упакованной записи. Отсюда два вывода:

1. обрыв на 536 — это не «сломанное имя», а реально нули до конца окна 0x80000: следующая пачка имён пула
   НЕ лежит подряд за блоком 0 (в UE5 блоки — разрозненные аллокации, а дамп не гарантирует полное покрытие приватной кучи);
2. sweep с порогом «64 цепных записи» как критерий приёмки непригоден: он обязан требовать глубину
   (512+ записей) либо доказательство содержимого, иначе порядковые номера для USMAP портятся мусором.

Девятая сборка (`2026-11-13-hunt`) делает и то, и другое: `WalkBackward` проверяет цепочку НАЗАД от
встреченного имени (153 записи у синтетики, 0 у строковой константы), охота идёт по `PersistentLevel`,
`PlayerController`, `RootComponent` на ЛЮБОМ выравнивании (sweep видел только странично-выровненные старты —
именно поэтому блоки 1..N могли быть не найдены, а не «отсутствовать»), нулевые слоты пула шагаются, но не и не
считаются доказательством, а блоки слабее 512 записей отсекаются (со счётчиком `sweep: N dropped`).
Синтетики: `syn_hunt.dmp` — блок 1199 имён на адресе `0x20001234` (не по границе страницы): охота нашла
(`back_entries=600/601`, `first_entry=0x20001234 NOT page-aligned`), sweep его не видел вообще; имена
в файле 1299, ординары 700/701 для `PersistentLevel`/`RootComponent`. `syn_pack.dmp` — регрессия чистая
(313 имён, `blocks=2 names=313`). ASan/UBSan чисто, `All core checks passed`.

Если после этого охота даст `deepest chain = 0` и ни одного валидированного блока — значит остального пула
в дампе нет физически, и единственный честный шаг: переснять дамп (`procdump -ma`), а не менять кодек.

### 6.2 Девятый прогон: три дампа дают один и тот же блок 0, и это measurement, а не догадка

`(2).DMP` и `PioneerGame.DMP` прогнаны без якоря (блок 0 найден маркером `None`):

```text
captured_ranges=40599  scanned_bytes=10670362624  marker_hits=7106 (None only)
anchor block_data=0xa7b10000 codec=packed_shift6_no_terminator entries=534 consumed=0x25c8
  Actor ordinal=57  Pawn ordinal=63  PersistentLevel ordinal=81
  hunt "PersistentLevel": 1 hit, deepest chain in front of a hit = 40
  verdict: no occurrence of a dynamically registered name ... (the rest of the pool is not captured)
  sweep: 11 candidate stream(s) below 512 entries dropped
  page sweep: 1 chain-validated block(s), total_names>=534
```

`pool_names_0.txt` и `pool_names_2.txt` — 534 строки, **побайтово identical** между двумя разными
сессиями. То есть блок 0 = статическая `EName`-таблица, её порядок и номера стабильны между запусками, и
наши ординары `Actor=57`, `Pawn=63`, `PersistentLevel=81`, `Team=103` — надёжны для этого билда. Всё, чего
в них нет, — динамические имена (World, SceneComponent, классы игры), они в блоках 1..N.

Отдельно зафиксировано: обратный проход по цепочке от `PersistentLevel` внутри блока 0 даёт только 40
записей вместо 81 — правило «предок заканчивается ровно перед заголовком» ломается на части записей
статической таблицы. Причина пока не измерена, но для охоты это значит, что порог глубины надо брать
ниже порога sweep'а: принято `max(8, min_entries/4)`, а мусор отсекает absorb-правило (хит внутри уже
принятого блока поглощается им, как в синтетике).

Сборка `2026-11-13-hunt2` добавляет то, чего не хватало для вывода о покрытии дампа: счётчик СЫРЫХ
вхождений каждого имени (`raw=`, отдельно «в модуле» и «снаружи»), 4 образца байтов перед хитами вне
модуля (вот где видно настоящий заголовок, если формат другой), `page map around the anchor` — статус
каждого 0x10000-соседа блока 0 (`uncaptured` / `zero-filled` / `non-zero` / `NAME STREAM`), и три разных
вердикта вместо одного: «имени нет нигде вне модуля → пула в дампе нет, снимай `procdump -ma`»; «имя есть,
но ни разу с packed-заголовком → формат другой, смотри raw[]»; «заголовки есть, цепочки короче порога →
блок не непрерывен в дампе». Синтетики: `syn_hunt` (нестраницный блок) 601/600 и 1299 имён в файле;
`syn_pack` регрессия 313; `syn_junk` (имён нет) → первый вердикт. ASan/UBSan чисто, `All core checks
passed`, `-Werror` зелёные. В игре ничего не запускалось.

Текущие сборки: `/arc_tool.exe` `1 254 912`, sha256
`2e16ad4889561295da240dc362fc125c469e7a36be03af812c9af4e3f3d5080f`, stamp `2026-11-13-write-probe`,
rev `660275fc2ae9d4b309220`. `arc_inject.exe` `958 464`, sha256
`2ec75e420b7314eebae10394997ebbb054fbb556b9c6bbb5ce0a59924fcfba7e` — лежит и в `/D7-build/`, и поверх
копии в `/Dumper7-ARC-Raiders/` (тот же `content_hash` `7afa14cf...`, так что ссылка на папку отдаёт уже
новую сборку). Сборка `-Werror` exit 0, `All core checks passed`; в игре ничего не запускалось.


## 7. Constructor lead, если FNamePool predicate не пройден

Для Object 4 vtable найден один RIP-relative LEA xref:

```text
Instruction VA: 0x144C364EB
Bytes:          48 8D 05 <disp32>
Target:         0x14D8952A0
```

Команда:

```powershell
.\arc_tool.exe dump-rip-xrefs "C:\Users\Malin\AppData\Local\Temp\PioneerGame (3).DMP" 0x14D8952A0
```

Следующий полезный анализ — прочитать код вокруг `0x144C364EB`, определить function start и field stores constructor. Это возможный путь к protected object header и классу Object 4. Constructor пока не дизассемблирован.

## 8. Закрытые ложные пути — не повторять

### RTTI

Обычный MSVC RTTI resolver неприменим к этим vtables:

```text
Object 1 locator = 0
Object 2 locator = 0x147EC0A90 — страница не захвачена
Object 3 locator = 0x14410A330 — ведёт в code, signature 0x480A8B48
Object 4 locator = 0x144C8FA60 — ведёт в code, signature 0xEC834856
```

Это instructions, не `CompleteObjectLocator`. On-disk `vtable-8` содержит другие преобразованные значения, поэтому EXE не заменяет runtime pages. Точный `/GR-` flag не доказан, но практический RTTI path закрыт.

### GUObjectArray

Полный scan dump `(3)` дал 17 candidates, все `index5_valid=0`. Четыре candidate с heap `first_chunk` проверены отдельно: chunks содержат x64 code, не UObject pointers. Все 17 отклонены. Стандартный sequential-index scanner не использовать повторно без новой object-header модели.

### Object 4 + 0x158

Сначала выглядело как `TArray<ULevel*>`:

```text
Object4 + 0x158 = 0x7CF5C010
Object4 + 0x160 = Count=199, Max=255
```

Чтение array показало сложные embedded elements с vtables `0x14D6D0E60`, `0x14D6D0FF0`, `0x14D6D1310`, вероятный stride `0x50`. **Это не доказанный Levels/Actors array.** Не читать как `ULevel*`.

### Viewport candidate

Опубликованный decrypt дал:

```text
Slot:      2
Key:       0xA74474574EF90345
Candidate: 0x1DBDA3550
World ref: candidate + 0x140 = 0x1F53F3D00
```

`0x1F53F3D00` имеет нулевой vtable и data-only body, не UWorld. Обязательная проверка `Viewport+0x140 == UWorld` провалена. Не использовать этот viewport или ShowFlags.

### Старые FName/GObjects constructor scans

```text
Constructor FNamePool: 19891 candidates, zero valid
Lazy paired-LEA:       17 pairs, zero valid
Old GUObjectArray:     6 candidates, sequential-index validation failed
```

Не повторять без изменения validation/layout.

## 9. Данные, необходимые для каждой целевой функции

### ESP

Минимальная цепочка данных:

```text
Confirmed World
→ PersistentLevel/Actors
→ Actor class/team/health
→ Actor RootComponent
→ world position
→ local camera POV
→ world-to-screen
```

Сейчас отсутствует каждый элемент после стабильного global chain.

### Minimap

Дополнительно к actor positions нужны local player position и camera yaw/rotation. Для radar можно использовать собственную rotation math без GameViewportClient, но camera/coordinates всё равно обязательны.

### Aim

После ESP нужны bone/skeleton/component transforms либо стабильная aim point, team filter, sensitivity calibration и input activation. Не выбирать aim offsets до подтверждения actor model.

### Trigger

Нужен надёжный crosshair target/team check или ray/visibility data. Не реализовывать на предположительных health/team offsets.

### Menu UI

ImGui menu можно писать независимо, но оно не даст игрового результата без reader. Не выдавать UI shell за реализованный ESP/Aim.

## 10. Рекомендуемый порядок продолжения

0. Если в `Dumper7-ARC-Raiders.zip` лежит SDK по `CL-1450810` — распаковать его в Dropbox и считать
   `Offsets.hpp`/`Dump.hpp`: это быстрее закрывает `GNames`/`GObjects`/`UWorld` и раскладку полей, чем
   восстановление по дампу. Тогда шаг 1–2 превращаются в валидацию готовых RVA на дампе.
1. `arc_tool probe <pid>` в живом матче — решить external vs internal не догадкой: если
   `private_region_reads` даёт `5 of 5`, внешний читатель живой; если `0 of 5`, external-маршрут закрыт
   и overlay имеет смысл только внутри процесса.
2. `dump-fname-blocks` по dump `(3)` (сначала `version`, хеш EXE выше). При `PREDICATE PASS`
   с `pool_referrers_image>0` имеем измеренный RVA `GNames` и рабочий FName reader.
3. Реализовать FName reader поверх найденного пула, затем class resolution и проверить четыре vtables и
   объекта из раздела 4 по имени класса.
4. При `anchors=0`: не возвращаться к generic scans — дизассемблировать функцию около `0x144C364EB` и
   восстановлять protected UObject header (шаги 7 раздела 7 остаются в силе).
5. Подтвердить Object 4 как UWorld через class name либо однозначные object relationships.
6. Найти PersistentLevel/Actors структурно и проверить массив по vtables/back-references, не только по
   `(ptr,count,max)` shape.
7. Восстановить RootComponent и position на нескольких actors; проверить движение/согласованность между
   dumps `(2)` и `(3)`.
8. Восстановить camera из Object 1/Object 2 или их camera manager; world-to-screen написать и
   протестировать отдельно от чтения игры.
9. Только затем overlay ESP и Minimap, после них Aim/Trigger и menu wiring.

## 11. Актуальный arc_tool

Ссылка:

https://www.dropbox.com/scl/fi/37w7un59wy4kc3slpw5xs/arc_tool.exe?rlkey=oes20rpmsq1wm7zkvcljap17e&dl=0

Актуальная версия (2026-11-13, `esp-chain` + `esp-actors` — вывод offset'ов ESP из дампа структурными
предикатами; внутри также dense-таблицы в `dump-fname-blocks`, обратная цепочка в
`dump-fname-layout`, `probe`/`probe-write`):

```text
Size:    1445376 bytes
SHA-256: 8648746873a50a7760b635647d56e315e0b5028547dea754f736a5d0184dfc18
build stamp: 2026-11-13-esp3  (Dropbox rev см. ниже)  <- слой функций §13
предыдущая: 1401344 / e29d482e316fb8d6f55dd99bc7ed81a3d75e8e29ec9ddc27f26f9ec01f61651c / 2026-11-13-esp2
предыдущая: 1364480 / e7d7097d5a451158d84aff92d4c7a035802d36a2d35d033bbecd272ae8d35ca0 / 2026-11-13-esp1
предыдущая: 1342976 / e77e85b598e0e240ce2a92aa2427d1450059490c4dbc87bfdd046d6aa87713e0 / 2026-11-13-hunt2
arc_inject.exe (впрыск закрыт измерением, оставлен для полноты): 958464 bytes
SHA-256: 2ec75e420b7314eebae10394997ebbb054fbb556b9c6bbb5ce0a59924fcfba7e
```

Живой процесс, замер 2026-11-13 (второй прогон, pid 5480 — главный процесс с окном игры):
`reader_handle=open`, все 8 прав выданы, НО `ReadProcessMemory` теперь отказывает на всех 5 приватных
регионах и на PEB (`win32_error=5`), `Toolhelp32Snapshot=failed 5`. В первом прогоне (pid 14292) было
`private_region_reads=5 of 5` и 77 модулей. То есть доступ к чтению живого процесса НЕ гарантирован и
зависит от момента замера — офлайн-дампы остаются единственным надёжным путём, на решения это не
влияет (имена всё равно восстанавливаются из `.DMP`).

'Шестой прогон — пул Валидирован на реальном дампе `(3)`: `anchor block_data=0xa6f10000
codec=packed_shift6_no_terminator entries=366 consumed=0x159a`, ординалы `Actor=57, Pawn=63,
PersistentLevel=81` (block 0), referrer `0x7fff725aeb90 -> 0xa6f10000 [heap]`. Цепочка обрывается на
+0x159a (не выровненный хвост — внутри блока есть запись неизвестного вида, главный подозреваемый —
wide), stride +0x10000 не дал block 1 (блоки аллоцированы раздельно). Ответ на это даёт сборка
`2026-11-13-pool-follow`: явный `anchor=0xa6f10000` (проход без маркерного скана, ~5–15 мин) печатает
`stop context` (hex на месте обрыва), `resync` (перезапуск цепочки после обрыва и размер пропуска) и
`pointer-array hunt` вокруг каждого referrer: прогоняет qwords окна ±0x1000 ищет максимальный прогон
указателей на декодируемые блоки (шаг 0x8) — это таблица блоков FNamePool; по найденному массиву
пересчитывает ординалы wanted-имён по всему пулу и помечает массив RVA-кандидатом если он в образе.
Седьмой прогон показал причину останова: на `+0x159a` лежит имя-путь
`"D:/tools/steamapps/common/Arc Raiders/..."` (len=106, заголовок `8a 1a`), и предикат символа
не пропускал пробел (0x20). Резолв: `IsNameCharacter` = 0x20..0x7e, wide-символ = любой ненулевой
u16. Плюс добавлен page sweep: проход по всем 0x1000-выровненным позициям всех диапазонов,
кандидат = 64+ идущие подряд packed-записи; поглощение смежных блоков в одну цепочку сохраняет
порядок; опциональный 10-й аргумент пишет файл `ordinal\tname` для всего пула (`usmap`--ready).
Ординалы до resync'а — нижняя граница (в выводе это сказано явно). Синтетика `syn_pack` прогоняется
зелёно в обоих режимах (discover и explicit anchor) под ASan/UBSan.

Пятый прогон (дампы нашлись в `C:\Users\Malin\AppData\Local\Temp`) дал решающее измерение:
`dump-read (3) 0xa6f10000 0x80` показывает формат записи — `u16 заголовок (len<<6 | чётные младшие
биты), имя СРАЗУ после заголовка, БЕЗ терминатора, одиночный 00 только для чётности`. Пример из
дампа: `1e 01 "None" 10 03 "ByteProperty" c0 02 "IntProperty" 00 34 03 "BoolProperty"`. Ни один из
прежних кодеков (требующих NUL) это декодировать не мог — пул лежал открытый, а `dump-fname-blocks`
видел только «37 похожих записей» на случайных NUL. Добавлен `packed_shift6_no_terminator` (первым в
кандидатах, wide-бит отключён), поиск маркеров игнорирует NUL в игле, валидация плотных таблиц —
только строгая цепочка (257 мусорных «таблиц» из кода DLL отпали), а stride для packed-блока = 0x10000.
Якорь теперь несёт `wanted names with pool ordinals` — порядковый номер имени во всём пуле, это ровно
то, что нужно USMAP (name index). Синтетика `syn_pack` (два блока по 0x10000, классы во втором) даёт
`PREDICATE PASS blocks=2 names=313`, `Actor block=1 ordinal=309` и `referrer [image] RVA=` — сценарий
GNames-кандидата проигран end-to-end до реального запуска.

Почему это сдвигает FName с мёртвой точки: в дампах `(2)`/`(3)` пул имён виден открытым текстом
(`IntProperty` на `0xa6f10014` у `(3)`, `0xa7b10014` у `(2)`), но строгий гейт «блок выровнен по
0x20000 и первая запись = None» его отбраковывал. Новый режим принимает регион по одной локальной
плотности декодируемых записей и делает по всем таким таблицам один объединённый проход за
ссылками — строка `[image] RVA=0x...` и есть кандидат на `GNames`. `dump-fname-layout` при этом
читаёт 0x400 до указанного адреса и цепляет записи назад до начала блока (`block start hint`).

Build выполнен Zig `x86_64-windows-gnu`, C++20, static, strict `-Werror`, exit code `0`. Portable core tests прошли. FNamePool scan на реальном dump ещё не запускался из-за запуска пользователем старого EXE. Ничего не проверено в live game.

PowerShell:

```powershell
cd "$env:USERPROFILE\Downloads"
Get-FileHash .\arc_tool.exe -Algorithm SHA256
```

---

## 12. `esp-chain`: вывод offset'ов из дампа без имён и без live-процесса (2026-11-13)

### Почему этот режим вообще появился

Публичные рабочие решалы по ARC Raiders (смотрели по прямой просьбе «чекни гитхаб»):

| репо | что внутри | вердикт |
|---|---|---|
| `xmodius/ArcRaiders-DMA-Dumper-v2` (12★, 2025-11-09) | «dumper» на MemProcFS, но offset'ы **хардкодом** (`GWorld=0x80E9950`, `PersistentLevel=0x38`, `AActors=0xA0`, `RelativeLocation=0x128`), проверка одна: `read(base+off) > 0x10000`, и те же константы обратно в `Offsets_Dumped.h` | переиспользовать нечего; его `PersistentLevel=0x38` противоречит второму репо (`0xE8`) — не считать вторым мнением |
| `a0yark/ArcRaidersRadar-dma-Radar` (23★, 2025-12-24) | `src/offsets.h` + `src/emu.cpp`: `GWorld` **не является обычным глобальным указателем** — это результат расшифровщика-чанка кода (`GWorld 0x4F80DFC..0x4F80EF4`, `GameInstance 0x2A5891F..0x2A58953`, `CameraManager 0x2A66AE9..0x2A66BF9`, `BoneBase 0x3076D50..0x3076E64`), который они исполняют в Unicorn с хуком на невалидную память (страницы дочитываются из живого процесса). Сам радар — заглушка (`// TODO: Add radar rendering logic here`), ценность = offset'ы + способ нахождения GWorld | единственный дешёвый валидатор, который у них есть: `read(uworld+0xE8)=L && read(L+0xE8)==uworld`. Это и есть структурный предикат, а не поиск по имени |

Отсюда два вывода, которые меняют план:

1. охота за «прямым `GWorld`/`GNames` в образе» — неверная модель этой игры, у глобалов нет статичного
   значения без выполнения чанка; наш путь «структурный граф из дампа» как раз не требует ни глобала,
   ни декодера;
2. класс имени не нужен вообще: UWorld/ULevel узнают друг друга по взаимной ссылке, TArray актёров
   опознаётся по трём qword'ам и «все элементы — объекты», позиция — голосованием по всем актёрам
   сразу. Ни один неверный offset не проходит ни один из этих предикатов, поэтому режим можно
   запускать на дампе и доверять строке `HIT`/`FAIL`.

Их декабрьские значения (для `pe_timestamp 0x6AEB721B` **не проверены**, арбитраж — только наше
голосование): `UWorld::PersistentLevel=0xE8`, `ULevel::OwningWorld=0xE8`, `ULevel::Actors=0x98` /
`ActorsCount=0xA0`, `UGameInstance::LocalPlayers=0x140`, `UPlayer::PlayerController=0x30`,
`APlayerController::AcknowledgedPawn=0x2A0` / `PlayerCameraManager=0x2D0`, `APawn::PlayerState=0x240` /
`RootComponent=0x130`, `USceneComponent::RelativeLocation=0x11C`.

### Что делает режим

```text
arc_tool esp-chain <game.dmp> <base> <image_size> [global_rva=0x108FEEC0] ["0xA0,0x250,0x160"] [out.ini]
```

Четыре стадии, каждая печатает `HIT` или явный `FAIL`:

1. **цепочка** — идёт `[base+global_rva] -> [+0xA0] -> [+0x250] -> [+0x160]`, для каждого объекта
   печатает vtable и вердикт `object_header=yes/NO` (vtable внутри образа = тот же предикат, что
   подтвердил четыре стабильных vtable в §4);
2. **UWorld/ULevel** — для каждого объекта цепочки и каждого `a` из
   `0x28,0x30,0x38,0x40,0x98,0xA0,0xE8,0xF0,0xF8,0x100,0x108,0x110,0x140,0x160` принимает пару, если
   `read(world+a)=level` и `read(level+b)=world` для некоторого  `b` из того же списка;
3. **массив актёров** — свип `level+0x20..0x400` шагом 8 в поиске `{Data,Num,Max}`, где 6 выбранных
   элементов подряд все проходят `LooksLikeObject`;
4. **позиция** — по N актёрам собираются **все** кандидаты `(actor+off -> component)`,
   `component+off -> FVector` (полоса: никакой ноль, `1.0e-2..1.0e6` по каждой оси, иначе это
   пол-указателя), и выигрывает большинство; затем второй проход читает координаты уже на победившей
   паре и печатает разброс по осям.

Пишет `[esp]` в ini: `image_base`, `global_rva`, `chain`, `world`, `persistent_level_off`, `level`,
`level_owning_world_off`, `level_actors_off`, `root_component_off`, `relative_location_off`, и
после всего — одну строку `[read path]` со всей цепочкой чтения целиком.

### Валидация (офлайн, синтетика)

`syn_esp.dmp` (139356 B) — дамп, собранный генератором под эти предикаты: образ держит глобал и
vtable'ы, куча — 4 объекта цепочки, круг UWorld/ULevel (`world+0x38 -> level`, `level+0xe8 -> world`),
`TArray {data,4,4}` в `level+0xA0`, у 4 актёров `+0x130 -> component -> +0x11C` со z-высотой 20..23.
Прогон печатал ровно правду: `component-offset votes: +0x130=7/4`, `location-offset votes: +0x11c=9/4`,
`positions at the winning offsets: 4/4`, `winner: [actor+0x130] -> component,
[component+0x11c] -> FVector`, `persistent_level_off = 0x38`, `level_actors_off = 0xa0`.

Три ветки отказа проверены тем же прогоном: неверная цепочка -> `FAIL: chain step +0x... is null or
uncaptured` (со ссылкой на 5-й позиционный аргумент), несхваченный глобал -> `FAIL: the global at
base+0x... is not captured in this dump`, пустой дамп-адрес -> `no round trip in 0x28..0x160`.

### Ловушка, которую починил второй проход

Первая версия голосовала «первым подходящим offset'ом» на актёра и выбирала `+0x100` вместо
`+0x11C`: младшая половина чужого vtable-указателя читается как субнормальные float'ы и проходила
старую полосу `>= 1.0e-3F`. Теперь (а) ровно ноль по любой оси = отказ, (б) полоса `1.0e-2..1.0e6`,
(в) собираются все пары `(component_off, location_off)` и ранжируются большинством, (г) координаты
дочитываются на победившей паре и печатается разброс — реальный уровень даёт тысячи юнитов по X/Y,
мусор даёт узкую полосу. `port`-харнесс собран с `-Wall -Wextra -Wpedantic -Werror`, чистый кросс-билд
Zig `x86_64-windows-gnu`, `tests/CoreTests.cpp` — `All core checks passed`.

### Ожидание от первого реального прогона

На `(3).DMP` возможны три исхода, и все три — ответ, а не шаг назад:

* `HIT world=... +0x?? -> level=...` на стадии 2 → массив актёров найден, offset'ов FNamePool для ESP
  больше не нужно вовсе, это разблокирует список юнитов;
* `object_header=NO` на объектах цепочки → цепочка ведёт не в UWorld, тогда надо сместить
  `global_rva`/`chain`, и `dump-chain-scan` (§4) уже умеет искать alternatives;
* `no round trip in 0x28..0x160` → либо конец цепочки не мир, либо взаимная ссылка обфусцирована;
  следующий шаг тогда — эмпирический перенос их `0xE8` (проверка одной парой, а не 14×14).

Старт-строка для пользователя (PowerShell, полные пути; `""` можно не писать — парсер классифицирует
хвост по форме, `.ini` отделяется от списка offset'ов по запятой):

```powershell
$exe = "$env:USERPROFILE\Downloads\arc_tool.exe"
$dmp = "C:\Users\Malin\AppData\Local\Temp\PioneerGame (3).DMP"
& $exe esp-chain "$dmp" 0x140000000 0x139F9000 0x108FEEC0 "$env:USERPROFILE\esp.ini" *> "$env:USERPROFILE\esp-chain.txt"
Get-Content "$env:USERPROFILE\esp.ini"
```

Ничего не проверено в live game; все значения — вывод офлайн-предикатов на одном дампе, они обязаны
повториться на втором дампе, прежде чем пойти в конфиг оверлея.
### Первый реальный прогон `(3).DMP` на `esp-chain` — измерено 2026-11-13

```text
image=0x140000000 size=0x139f9000 global=0x1508feec0   captured_ranges=63459
obj[0]=0x1390f2500 vtable=0x14e03b0b0 object_header=yes
obj[1]=0x296f04ed0 vtable=0x14e2802e0 object_header=yes
obj[2]=0x296a6a6f0 vtable=0x14d65be30 object_header=yes
obj[3]=0x7f9d55c0  vtable=0x14d8952a0 object_header=yes
[uworld/level] no round trip in 0x28..0x160 on any chain object
[level]        no TArray of objects in the first 0x400 bytes of any level candidate
SUMMARY sampled_objects=4 level_hits=0 actors=0 position_actors=0
```

Что это уже знает, и это не «снова диагностика»:

* все четыре звена цепочки `0x108FEEC0 -> +0xA0 -> +0x250 -> +0x160` живые и в дампе, и каждый объект
  имеет корректный UObject-заголовок (vtable внутри образа, слот vtable указывает в код). То есть
  цепочка §4 не протухла на этом билде — отвалилось именно предположение «последний объект = UWorld»;
* четыре разных vtable (`0x14e03b0b0`, `0x14e2802e0`, `0x14d65be30`, `0x14d8952a0`) = четыре разных
  класса, ни один из них не обменивается уровнем по plaintext-указателю в окне `0x28..0x160`;
* ни у одного из них нет и массива объектов в первых 0x400 байтах, т.е. это не `ULevel` и не владелец
  `AActor**`. Вывод: обход «от глобала» на этом билде ведёт не туда, и спорить с этим бесполезно —
  нужен обход «от данных».

Отсюда `esp-actors`: вместо того чтобы угадывать, где лежит мир, он один раз читает все захваченные
байты дампа и ищет любую структуру `{Data, Num, Max}`, у которой `Num` элементов подряд — указатели на
объекты с в-image vtable. Дальше по каждому найденному массиву голосует пару `(actor+off -> component,
component+off -> FVector)` и берёт тот массив, где позиции согласуются и расходятся по осям на сотни
юнитов. Имена, `FNamePool`, глобалы и live-процесс не участвуют вообще.

Синтетический гейт (`tools/offline-port/run.sh`, переехал в репозиторий, потому что `/tmp` между
сессиями вычищается): дамп содержит массив актёров на 64 элемента **и** подставной массив на 128
объектов без позиций. Режим обязан найти оба, поставить подставной в кандидаты, и выбрать настоящий —
что он и делает: `array[1] … num=64 … owner=0x200004100 at +0xa0` (то есть уровень угадан правильно),
`component=+0x130 location=+0x11c`, `positions=48/48`, `spread X=2491 Y=1363 Z=329`, а `array[0]`
(подставной) получает `positions=0` и не помечается как настоящий. Тот же прогон проверяет `esp-chain`
после рефакторинга стадии 4: раунд-трип `+0x38/+0xe8`, `num=64`, `winner +0x130/+0x11c`,
`positions 48/48`, и что сломанная цепочка печатает `FAIL` и не пишет ini.

Побочный эффект: `LooksLikeObjectArray` и свип теперь принимают `Num` до 2 000 000 (раньше потолок был
200 000 — на реальной карте уровня UE такое число актёров достижимо, и гейт молча отбраковывал бы
настоящий массив).

Команда для пользователя (PowerShell, полные пути; 4-й позиционный — порог `Num`, 5-й — куда писать):

```powershell
& "$env:USERPROFILE\Downloads\arc_tool.exe" esp-actors "C:\Users\Malin\AppData\Local\Temp\PioneerGame (3).DMP" 0x140000000 0x139F9000 256 "$env:USERPROFILE\esp-actors.txt" *> "$env:USERPROFILE\esp-actors.log"
```

Ожидание: блок `[candidates] N object arrays`, затем по строке на массив с `vote:`/`spread`, и если
хотя бы один массив согласуется — строка `[best] … positions=X/Y` и файл с `[positions]`. Ответом может
быть и `0 object arrays of >= 256 elements` — это значит, что в дампе нет ни одного захваченного
массива объектов такого размера, и тогда путь один: дамп с захваченной кучой целиком.
---

## 13. Слой функций: `esp-config` → `esp-export` → `esp-overlay` (2026-11-13, build `2026-11-13-esp3`)

Второй реальный прогон (`esp-actors` на `(3).DMP`) закрыл тему «вывести оффсеты из этого дампа»: свип
нашёл 10 массивов указателей на объекты (1 403 205 / 589 832 / 508 615 / 328 048 / …), и ни один не
оказывается списком позиционированных актёров — `positions=0..4`, `spread=-2e+30`. Отрицательный
`spread` и `-nan` в строках — это не «данные странные», а наш же баг: полоса величин в `FloatTriple`
пропускала NaN (сравнения с NaN ложны), а `Sane()` имел запасную ветку «4 строки = уже похоже». Оба
исправлены: единственное определение «это может быть координатой» теперь живёт в `src/Esp.cpp`
(`IsPlausiblePosition` / `IsPositionCandidate`, через `std::isfinite`), и `Sane()` обязан увидеть
конечный разброс больше 20 юнитов — бесплатный проход убран. Тот же прогон на тех же данных теперь
печатает `(rejected: the agreed rows do not spread over a level, so they are fields that merely look
like coordinates)` вместо ложного «consistent with a real actor list».

Дальше дамп крутить бессмысленно, поэтому сделан то, что раньше откладывалось: функции, которые работают
с оффсетами, а не ищут их. `src/Esp.cpp` — переносимый core без Win32, без дампа и без рендера:

* `EspOffsetSet` + парсер `[esp]`-секции (`ParseEspConfig`/`LoadEspConfig`): цепочка, `world_va`
  (пропуск цепочки, если адрес мира взят откуда-то ещё), `persistent_level_off`, `level_actors_off`,
  `actor_array_data`/`actor_array_num`, `root_component_off`, `relative_location_off`, `health_off`,
  `max_health_off`, `team_off`, `local_*`, `view_yaw/pitch_degrees`, `fov_degrees`, `screen_*`,
  `actor_radius_cm`, `local_controller_va` + `camera_*`;
* `CameraBasis` / `WorldToScreen` / `ScreenRadiusPixels` / `DistanceMetres` — юниновская система
  (X вперёд, Y вправо, Z вверх, cm, горизонтальный FOV, вертикаль из аспекта), с обрезкой по near-плоскости,
  чтобы то, что за камерой, никогда не нарисовалось;
* `ReadActors` — обход массива по `IMemory` (интерфейс: qword/float/dword), пропуск строк с
  неправдоподобной позицией; `ReadLocalView` — камера из того же снапшота;
* `SelectAimTarget` (ближайшая к прицелу спроецированная строка в конусе) и `IsOnAimPoint` (условие
  триггера) — чистые функции, не связанные с проекцией;
* `ToJson(rows, offsets, total, as_js, note)` — один документ: строки + оффсеты, которые их дали, +
  примечание; `as_js` оборачивает в `window.ARC = …;`, потому что `fetch()` локального `.json` с `file://`
  запрещён во всех браузерах, а `<script src>` — нет;
* `OverlayHtml()` — сама страница оверлея (canvas, авто-обновление `esp-data.js` раз в 300 мс,
  масштабирование под реальный размер окна, полоски HP, подписи дистанции/команды, центральный маркер).

Режимы в `arc_tool`:

```text
esp-config  <out.ini>                     пустой [esp]-шаблон со всеми ключами и комментариями
esp-export  <dmp> <base> <size> <cfg.ini> [out.js|out.json] [rows]
esp-overlay <out.html>                    просмотрщик для esp-data.js
```

`esp-export` сам добирается до массива актёров: если в ini есть `actor_array_data`/`actor_array_num`
(их пишет `esp-actors` и `esp-chain`) — использует их; если есть `world_va` — читает
`[world+persistent_level_off]+level_actors_off`; иначе идёт по `chain` от `global_rva` и пробует каждый
объект как мир. Не найдено — печатает причину и ничего не пишет, а не выдаёт мусор.

Проверка (всё офлайн, `tests/CoreTests.cpp` + `tools/offline-port/run.sh`, живого процесса не трогали):
`TestEspMath` — базис камеры, вертикальный FOV из аспекта, проекция в центр, попадание на верхнюю грань,
отказ «за камерой» и «внутри near», обратный масштаб коробки, отказ NaN/денормалов;
`TestEspConfigAndRows` — парсер ini, обход фейковой памяти (две строки читаются, строка с NaN
отбрасывается, health/team читаются, `hp: null` вместо выдуманного нуля), JSON/JS, `SelectAimTarget`
(пустой конус ничего не берёт), `IsOnAimPoint`; `run.sh` — весь конвейер на синтетике: `esp-actors` →
ini → `esp-export` → `64 of 64 actors carry a plausible position`, `dist 22.38`, `window.ARC` в начале
файла, и ручной ini без всякого свипа даёт `distance 0..N` с «off view» на самом локальном актёре.
`All core checks passed`, кросс-билд Zig чистый с `-Wall -Wextra -Wpedantic -Werror`.

Что это значит практически: как только набор оффсетов появится (из своего дампа другим путём, от
человека, у которого внутренний работает, или из обновлённого публичного — см. §12), функции уже готовы,
и ничего кроме ini-файла менять не надо: `esp-export` отдаёт строки, `esp-overlay` их рисует. В live game
не проверялось по-прежнему ничего: оверлей и математика проверены на синтетике и юнитах, а не на экране.
