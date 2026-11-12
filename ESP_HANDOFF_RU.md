# ARC Raiders — handoff для ESP / Aim / Trigger / Minimap / menu-ui

## 1. Целевая задача

Нужен рабочий инструмент для ARC Raiders со следующими функциями:

- ESP: игроки, имена, дистанция, health, box/skeleton — после восстановления соответствующих полей;
- Minimap/Radar: координаты локального игрока, других actors и camera/yaw;
- Aim: world-to-screen, выбор цели, кости/точка прицеливания, калиброванная чувствительность;
- Trigger: активация только при валидном наведении на противника;
- Menu UI: ImGui, Insert для меню, клавиши функций, настройки overlay.

Сейчас **ни одна из этих runtime-функций не реализована и не проверена**. Нет actor list, координат, camera, team/health или world-to-screen.

Предпочтительная архитектура после получения offsets: external reader + transparent ImGui overlay. Internal DLL потребуется только для hooks/direct engine calls. Стандартная usermode инъекция на текущей системе не сработала: `VirtualAllocEx` error `5` до `LoadLibraryW`.

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

## 6. Активный FNamePool recovery — первый следующий шаг

Добавлена команда:

```text
dump-fname-pool <DMP> <ImageBase> <ImageSize>
```

Она сканирует 10 известных USMAP names:

```text
World
Actor
Pawn
GameInstance
LocalPlayer
PlayerController
PlayerCameraManager
PersistentLevel
RootComponent
/Script/Engine
```

Predicate приёма pool:

1. ANSI FName header: length shift `6`, string offset `2`, wide bit снят.
2. Block base: `entry & ~0x1FFFF`.
3. Полный `0x20000` block присутствует в dump.
4. `Chunks[]` находится в heap вне image.
5. Минимум 8 валидных block pointers.
6. Pool reference находится в heap вне image.
7. Повторный decode по `(blockIndex << 16) | (entryOffset / 2)` точно совпадает с USMAP name.

Команда:

```powershell
.\arc_tool.exe dump-fname-pool "C:\Users\Malin\AppData\Local\Temp\PioneerGame (3).DMP" 0x140000000 0x139F9000
```

**Важно:** пользователь случайно запустил старую EXE, поэтому этот scan ещё не выполнен. Нужен SHA-256:

```text
9cbf241d21024442e16ee37e5150327f054d19da53e829d1072a47d83fc96d2c
```

Ожидаемый отчёт содержит `scanned_bytes`, `raw_hits`, `filtered`, `rejected_runs`, `chunk_candidates`, `validated_pools`. Принимать только `PREDICATE PASS`; при `validated_pools=0` результат не принят.

Ранее найден plaintext FName block `0xA6A00000` в dump `(2)`, но глобальный pool не был валидирован. Не переносить этот heap VA в dump `(3)`.

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

1. Запустить актуальный `dump-fname-pool`, проверить SHA-256 EXE, получить полный счётчик отчёта.
2. При `PREDICATE PASS`: реализовать FName reader, затем class resolution и проверить четыре vtables/объекта.
3. При `validated_pools=0`: дизассемблировать function около `0x144C364EB`, восстановить constructor stores и protected UObject header; не возвращаться к generic scans.
4. Подтвердить Object 4 как UWorld через class name либо однозначные object relationships.
5. Найти PersistentLevel/Actors структурно и проверить массив по vtables/back-references, не только по `(ptr,count,max)` shape.
6. Восстановить RootComponent и position на нескольких actors; проверить движение/согласованность между dumps.
7. Восстановить camera из Object 1/Object 2 или их camera manager; сделать и протестировать world-to-screen отдельно.
8. Только затем overlay ESP и Minimap, после них Aim/Trigger и menu wiring.

## 11. Актуальный arc_tool

Ссылка:

https://www.dropbox.com/scl/fi/37w7un59wy4kc3slpw5xs/arc_tool.exe?rlkey=oes20rpmsq1wm7zkvcljap17e&dl=0

Актуальная для FNamePool версия:

```text
Size:    1072128 bytes
SHA-256: 9cbf241d21024442e16ee37e5150327f054d19da53e829d1072a47d83fc96d2c
```

Build выполнен Zig `x86_64-windows-gnu`, C++20, static, strict `-Werror`, exit code `0`. Portable core tests прошли. FNamePool scan на реальном dump ещё не запускался из-за запуска пользователем старого EXE. Ничего не проверено в live game.

PowerShell:

```powershell
cd "$env:USERPROFILE\Downloads"
Get-FileHash .\arc_tool.exe -Algorithm SHA256
```
