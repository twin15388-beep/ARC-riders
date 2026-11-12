# ARC Raiders — полный конспект работы

Обновлено после проверки viewport-кандидата `0x1DBDA3550` в дампе `PioneerGame (2).DMP`.

## 1. Что мы делаем

Исходная цель — собственный проект для ARC Raiders: восстановление внутриигровых структур, генерация SDK и последующая разработка функций на C++.

Сейчас реально существует не внутриигровой чит, а исследовательский инструмент `arc_tool.exe`:

- читает PE-файл игры;
- читает MDMP-дампы без необходимости открывать процесс;
- ищет сигнатуры и указатели;
- проверяет pointer chains;
- читает USMAP;
- содержит отдельный, специфичный для сборки viewport-decryptor;
- имеет переносимые тесты для собственных алгоритмов.

**ESP, gameplay-функции, генерация SDK и запуск внутри игры пока не реализованы и не подтверждены.**

## 2. Идентичность исследуемой игры

```text
Процесс/модуль:       PioneerGame.exe
Product:              pioneer_2.03.x-CL-1450810
Engine file version:  5.7.4.0
Размер EXE:           322041712 байт
PE timestamp:         0x6AEB721B
Image base:           0x140000000
Image size:           0x139F9000
```

Основной gameplay-дамп:

```text
C:\Users\Malin\AppData\Local\Temp\PioneerGame (2).DMP
Размер: 10 681 401 676 байт
Создан: 2026-11-12 20:52:23 локального времени
```

Все недавно подтверждённые значения относятся именно к этой сборке и этому дампу. Их нельзя автоматически переносить на другой патч или другой момент запуска: heap-указатели изменятся.

## 3. Что уже реализовано в репозитории

```text
src/Main.cpp          CLI и команды
src/DumpFile.*        MDMP, VA lookup, heap filtering, reads, chains, scans
src/PeFile.*          Информация о PE
src/Process.*         Работа с процессом Windows
src/Scanner.*         Сканирование
src/Pattern.*         Паттерны и wildcard
src/Chain.*           Pointer chains
src/Config.*          INI-конфигурация
src/Usmap.*           Ограниченный parser uncompressed USMAP v0–v4
src/ArcDecrypt.*      Отдельный build-specific decrypt-кандидат
src/Injector.cpp      Экспериментальный injector, в игре не сработал
tests/CoreTests.cpp   Переносимые тесты
config/arc_raiders.ini Измеренная идентичность; рабочие сигнатуры не заданы
HANDOFF.md            Техническая история исследования
STATUS_RU.md          Этот общий конспект
```

Проверки, которые действительно выполнялись:

- компиляция с строгими warnings-as-errors;
- переносимые core tests;
- AddressSanitizer и UndefinedBehaviorSanitizer;
- проверка реального USMAP;
- проверка Windows AMD64 PE;
- тест decrypt на реальных байтах дампа.

CMake в среде отсутствовал, поэтому фактически использовались прямые команды `g++` и Zig cross-compiler. Windows Runtime и MSVC здесь не тестировались.

## 4. Live-доступ и инъекция

Попытки работать с запущенным процессом не удались:

- обычное чтение/перечисление модулей блокируется правами;
- `VirtualAllocEx` для правильного PID возвращает ошибку `5` (`ACCESS_DENIED`);
- сбой происходит до `LoadLibraryW`;
- DLL Dumper-7 также не была загружена в игру.

Это не доказывает отсутствие нужных структур. Это означает только отсутствие live-доступа. Неизменённые попытки инъекции повторять бессмысленно.

Дальнейшая работа поэтому велась по MDMP-дампам.

## 5. USMAP

Пользователь предоставил Dropbox-архив:

```text
dropbox/1450810_[unknowncheats.me]_.zip
```

Внутри оказался только USMAP:

```text
1450810.usmap
Размер: 5 435 248 байт
SHA-256: 313d29e66a93e96e98d65353416e1df90bff31638daa4fd3ce3a8a50fb228f26
```

Результат проверки:

```text
Формат:       uncompressed USMAP v4
Names:        113 898
Enums:        3 755
Structs:      29 100
Extensions:   CEXT / PPTH / ENVP
```

Parser сверялся с `pbzusmap`, CUE4Parse и UE4SS. Первоначальное предположение о повреждении/desynchronization оказалось неверным: оставшиеся байты были extension-блоками.

Важно: schema/property indices в USMAP — **порядковые индексы, не offsets в памяти игры**. Наличие USMAP само по себе не даёт `GObjects`, имена live-объектов или готовый SDK.

## 6. FName и GObjects — что не удалось

Обнаружен plaintext FName block:

```text
VA:                  0xA6A00000
ANSI length shift:   6
Header offset:       0
String offset:       2
```

Но глобальная таблица не восстановлена:

- constructor-based FNamePool scan: `19 891` кандидатов, ни одного валидного;
- lazy paired-LEA scan: `17` пар, ни одного валидного;
- full-memory GUObjectArray scan: `6` кандидатов, все отклонены sequential-index validation.

Поэтому сейчас невозможно надёжно получить имя класса UObject по его стандартным полям. Это главное препятствие для окончательной идентификации найденных объектов.

## 7. Старые публичные offsets — отклонённые или непроверяемые

Для старого дампа были отклонены:

```text
0x14DB48E80
GWorld entry 0x1509BB1C0
Pointed candidate 0x146BFE650
Accessor 0x140391A80
Alternate GWorld 0x14E011D18
```

`0x146BFE650` оказался областью обычных C++/FString-функций, а не FUObjectArray/decryptor. `0x140391A80` также не является GUObjectArray accessor.

Следующие адреса просто не были захвачены в дампе, поэтому о них нельзя сделать вывод:

```text
0x14623C820
0x14AD2FC50
0x14AD8EE10
0x14AD30540
0x1404AAB20
0x1403AA3C0
```

Старые публикации других патчей не принимались без подтверждения на нашем дампе.

## 8. Pointer-chain scan и важная ошибка арифметики

Публичная цепочка с форума:

```text
RVA global: 0x108FEEC0
Затем:      +0xA0 -> +0x250 -> +0x160
```

Правильное сложение:

```text
0x140000000 + 0x108FEEC0 = 0x1508FEEC0
```

Ранее ошибочно использовался `0x1509FEEC0`. Нули по ошибочному VA не являются опровержением публичного RVA.

Развитие scanner:

1. Первая версия остановилась на cap `4 172 216` qwords и содержала duplicates/image pointers.
2. Вторая остановилась на cap `10 802 494` qwords и содержала heap-table noise.
3. Третья фильтровала значения вне heap, убирала duplicates и требовала in-image vtable для каждого значения.
4. Третья версия обработала `17 916 928` qwords, нашла `25 905` pointer chains и ровно **одну уникальную UObject-shaped цепочку**.

Первые два scan были неполными; их нельзя считать отрицательным результатом.

## 9. Найденная цепочка — текущий наиболее сильный результат

```text
Global VA       0x1508FEEC0
  ↓ read qword
LocalPlayer?    0x1DBCF5730
  ↓ +0xA0
Controller?     0x2A0498890
  ↓ +0x250
Intermediate    0x2A0548A70
  ↓ +0x160
World?          0x1F53F1D00
```

Vtables:

```text
LocalPlayer?:   0x14E03B0B0
Controller?:    0x14E2802E0
Intermediate:   0x14D65BE30
World?:         0x14D8952A0
```

Дополнительные структурные совпадения:

```text
LocalPlayer + 0xA0   = 0x2A0498890 (тот же Controller?)
Intermediate + 0x158 = 0x2A0498890 (обратная ссылка на Controller?)
Intermediate + 0x160 = 0x1F53F1D00 (тот же World?)
```

Все значения имеют captured heap storage и vtable внутри game image. Это сильное структурное подтверждение именно в одном дампе.

**Ограничение:** имена классов не прочитаны. Поэтому знаки `?` важны: формально это пока UObject-shaped chain, а не доказанные `EmbarkLocalPlayer → PlayerController → … → UWorld`.

## 10. Viewport — вся история и итог

Публичное описание утверждало:

```text
Slot hash:       адрес LocalPlayer + 0xF0
Ciphertext:      LocalPlayer + 0x100 + slot * 0x20, 16 байт
Key seed:        адрес base + 0x10421C80
World check:     GameViewportClient + 0x140 == UWorld
ShowFlags:       примерно GameViewportClient + 0x388
```

Точная опубликованная формула была реализована отдельно в `ArcDecrypt.*`.

На реальных байтах получилось:

```text
Slot:                2
Key:                 0xA74474574EF90345
Decrypted candidate: 0x1DBDA3550
Candidate vtable:    0x14E20BE20
Candidate + 0x140:   0x1F53F3D00
Chain endpoint:      0x1F53F1D00
```

Адреса миров не совпали. Последующий `dump-read 0x1F53F3D00 0x600` показал:

- первый qword равен нулю;
- отсутствует UObject vtable;
- дальше обычный блок данных, а не UWorld.

**Итог:** decrypt детерминированно даёт правдоподобный heap/UObject-shaped адрес, но обязательная World back-reference проваливается. `0x1DBDA3550` нельзя считать подтверждённым GameViewportClient и нельзя использовать для записи ShowFlags.

Во время исследования были две собственные ошибки, которые исправлены и не должны повторяться:

1. Банк ошибочно назывался `LocalPlayer+0x140`; правильный банк для этой формулы — `LocalPlayer+0x100`.
2. До обращения к первоисточнику была записана другая SplitMix-подобная формула. Она заменена точной опубликованной формулой. Теперь реальный тест действительно подключён к `main()` тестов и проверяет slot/key/pointer.

## 11. Что сейчас считается доказанным

Доказано:

- идентичность EXE;
- работоспособность MDMP/PE/USMAP tooling;
- полный разбор предоставленного USMAP;
- существование уникальной UObject-shaped pointer chain;
- внутридамповые pointer/back-reference совпадения;
- арифметика опубликованного viewport decrypt;
- провал viewport World validation;
- прохождение собственных strict/sanitizer tests.

Не доказано:

- точные имена классов объектов цепочки;
- что `0x1F53F1D00` является UWorld;
- настоящий GameViewportClient;
- GNames/GUObjectArray;
- рабочий SDK;
- чтение игроков/actors/positions;
- ESP или gameplay-функции;
- выполнение кода внутри игры.

## 12. Актуальный инструмент

Стабильная ссылка:

https://www.dropbox.com/scl/fi/37w7un59wy4kc3slpw5xs/arc_tool.exe?rlkey=oes20rpmsq1wm7zkvcljap17e&dl=0

Последняя опубликованная версия:

```text
Размер:   1 056 768 байт
SHA-256:  ea07bd9449c842b2a4622f93c3255e567a37901334fada9509a5ebb57867bcea
Dropbox rev: 66017b6ad6d994b309220
```

Последующие commits меняли только документацию после отклонения viewport.

PowerShell не ищет EXE в текущей папке без `.\`:

```powershell
cd "$env:USERPROFILE\Downloads"
.\arc_tool.exe ...
```

Пример чтения:

```powershell
.\arc_tool.exe dump-read "C:\Users\Malin\AppData\Local\Temp\PioneerGame (2).DMP" 0x1F53F1D00 0x600
```

Основные команды:

```text
file <EXE>
dump <DMP>
dump-read <DMP> <VA> <Size>
dump-chain <DMP> <StartVA> [Offsets...]
dump-chain-scan <DMP> <BaseVA> <Size> <Offsets...>
dump-strings <DMP> <Range>
dump-xrefs <DMP> <Address>
dump-scan <DMP> <Pattern>
usmap <USMAP>
usmap-struct <USMAP> <StructName>
decrypt-viewport <LocalPlayer> <ModuleBase> <0x100HexBytes>
```

`decrypt-viewport` оставлен как исследовательская команда, а не как подтверждённый игровой resolver.

## 13. Следующий этап

Приоритет — не дальнейший слепой подбор viewport и gameplay-offsets, а восстановление способа идентифицировать объекты:

1. Найти валидный объектный массив/диспетчер имён для этой сборки.
2. Проверить классы четырёх объектов найденной цепочки.
3. Только после подтверждения `UWorld` исследовать Levels/Actors.
4. Найти viewport через подтверждённые объектные связи либо отклонить публичный метод окончательно.
5. После появления class/name resolution генерировать минимальный SDK и лишь затем проектировать overlay/ESP.

Это медленнее, чем копировать offsets, но исключает построение проекта на правдоподобных, однако неверных указателях.

## 14. Продолжение: RTTI resolver

Добавлена команда `dump-rtti <DMP> <ImageBase> <VtableVA>...`. Она читает MSVC x64 `CompleteObjectLocator` через `vtable-8`, затем `TypeDescriptor` по RVA от image base и выводит decorated C++ class name. Это независимый от GNames/FNamePool способ проверить найденные vtables. На момент добавления результаты на игровом дампе ещё не получены.
