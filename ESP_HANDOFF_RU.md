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

`Dumper7-ARC-Raiders.zip` в handoff ранее не фигурировал. Если это вывод Dumper-7 по текущему CL, он
закрывает и `GNames`/`GObjects`/`UWorld` RVA, и раскладку полей, то есть обходит весь раздел 6 — но
содержимое надо валидировать на `CL-1450810`, а не принимать как есть. Из песочницы zip не открыть:
исходящая сеть разрешена только для github/npm/pypi, `curl` на
`*.dl.dropboxusercontent.com` упал с `SSL_ERROR_SYSCALL` (проверено 2026-11-13). Текстовые файлы
Dropbox-коннектор отдаёт в `/home/user/ARC-riders/dropbox/`, поэтому распакованный `Offsets.hpp` или
`Dump.hpp` можно читать оттуда.

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

## 6. FNamePool recovery — актуальный шаг (2026-11-13, после двух прогонов)

Оба запуска, которые я просил, сделаны, и каждый дал измеренный факт.

`dump-fname-blocks` на реальном дампе (`C:\Users\Malin\AppData\Local\Temp\PioneerGame (3).DMP`,
12 956 266 993 байта):

```text
build=2026-11-13-fname-blocks-probe
block_size=0x20000 min_entries=64 expected_first="None" captured_ranges=63459
discovery scanned_bytes=12943527936 marker_hits=1140 region_probes=1004 anchors=0
SUMMARY build=2026-11-13-fname-blocks-probe anchors=0 validated_pools=0
```

Значит: маркеров `None\0` в памяти много (1140), но ни одна из двух кодировок заголовка записи, которые
я вносил в `Names.h` (`measured_shift6_wide0_str2`, `alt_len_bits_0_9_wide10`), не разворачивает оттуда
плотный поток за `min_entries=64`. Это вывод про мои две догадки, а не про то, что пула нет. Третьу догадку
я добавлять не буду — layout надо снимать с байтов.

`probe 14292` на живом процессе: `current_process_elevated=yes`, `se_debug_privilege=enabled`, все восемь
прав выданы, `reader_handle=open`, `vm_read_at_image_base=MZ ok`, `private_region_reads=5 of 5`,
`toolhelp_snapshot=ok modules=77`. Внешнее пользовательское чтение работает полностью — architecture
решена в пользу external reader + overlay, старый `VirtualAllocEx error 5` больше не аргумент.
`live image_base=0x7ff7e6370000` (ASLR) против дамп-базы `0x140000000`, так что любое число из дампа
пересчитывается через живую базу. Обход PEB в той сборке был мой баг (печатал 2 модуля и `ntdll.dll
base=0x1c9e14cc3d0`), а `PioneerGame.exe size=0x1d82000` из LDR-записи противоречит PE-заголовку дампа
(`0x139F9000`) — поэтому размер образа больше не берётся из LDR.

Что добавлено в инструмент вместо новой догадки:

- `dump-fname-blocks` при нуле якорей ранжирует просмотренные области по плотности строк и печатает для
  топ-8: число ASCII-пробегов, байтовый шаг между соседними строками, первое имя и 0x40 raw-байт. Единый
  шаг = фиксированный stride записей; чередующиеся шаги = лишние поля в записи; заголовок виден глазами.
- `dump-fname-layout <DMP> <VA> [window] [max_hits]` и `live-fname-layout <pid> <VA> [window] [max_hits]`
  применяют то же измерение к любому адресу — в дампе и в живой памяти, через один и тот же
  `arc::PrintNameLayout`. Он печатает и имя, и 16-битное слово прямо перед началом строки, то есть поле
  длины/ширины видно без предположения о сдвиге.
- `probe` теперь сверяет обход PEB с Toolhelp (`peb_walk validation: modules=N bases_also_in_toolhelp=K`) и
  печатает `live_pe_headers ... SizeOfImage`, секции и `last_page_readable` из самого образа в памяти.
  Расхождение с Toolhelp — сигнал «offsetы записи неверны, доверяй Toolhelp».

```powershell
.\arc_tool.exe version    # жду build=2026-11-13-layout-probe
.\arc_tool.exe dump-fname-blocks "C:\Users\Malin\AppData\Local\Temp\PioneerGame (3).DMP" 0x140000000 0x139F9000
.\arc_tool.exe probe <pid>
```

EXE в Dropbox: `/arc_tool.exe`, rev `660263c4bcaa54b309220` (заменён на сборку
`2026-11-13-layout-probe`, размер `1,245,184`, SHA-256
`17ed9f27a15d91762c6fdd82626e382cbcdca77af81d2e64f8b610f492fa17c1`). В репозитории тот же файл —
`out/arc_tool.exe`, сам `out/` в git не попадает.

Проверено на синтетических MDMP: плотный дамп по-прежнему даёт `PREDICATE PASS blocks=3 names=210`
(регрессии нет), а дамп с 8-байтовым «хвостом» в записи, где строгий обход ломается, даёт
`ascii_run ... runs=64 string_to_string=0x16x63` + `partial ... gaps=0x10x63` — то есть инструмент честно
показывает реальный шаг вместо тихого `anchors=0`. В live game ничего не запускалось.

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

Актуальная версия (2026-11-13, `dump-fname-blocks` + `dump-fname-layout` + `live-fname-layout` + `probe`):

```text
Size:    1245184 bytes
SHA-256: 17ed9f27a15d91762c6fdd82626e382cbcdca77af81d2e64f8b610f492fa17c1
build stamp: 2026-11-13-layout-probe
```

Build выполнен Zig `x86_64-windows-gnu`, C++20, static, strict `-Werror`, exit code `0`. Portable core tests прошли. FNamePool scan на реальном dump ещё не запускался из-за запуска пользователем старого EXE. Ничего не проверено в live game.

PowerShell:

```powershell
cd "$env:USERPROFILE\Downloads"
Get-FileHash .\arc_tool.exe -Algorithm SHA256
```
