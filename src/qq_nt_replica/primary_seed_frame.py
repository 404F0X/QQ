from .primary_material_generation import _retained
from .primary_material_prepare import _address, _auxiliary, _binary, _lookup, _mask, _right
from .primary_material_rounds import _less, _load, _next, _store


_LOOKUPS = ({'auxiliary': {1129: 1719746561,
                1135: 16951,
                1141: 745730195,
                1144: 32278,
                1149: 1053958659,
                1152: 1949491603,
                1160: 2070995459,
                1164: 31598,
                1165: 2128474628,
                1171: 557113860,
                1174: 64364,
                1175: 1359520259,
                1177: 48495,
                1178: 1921233411,
                1181: 52582,
                1182: 2114085379,
                1185: 44846,
                1186: 466383364,
                1187: 1255308771,
                1190: 396526883},
  'flag0': (1144, 1164, 1174, 1181),
  'comparisons': (1149, 1152, 1187),
  'cells': (1127,
            1129,
            1130,
            1131,
            1132,
            1133,
            1135,
            1136,
            1137,
            1138,
            1139,
            1141,
            1142,
            1143,
            1144,
            1145,
            1146,
            1147,
            1148,
            1149,
            1150,
            1151,
            1152,
            1153,
            1154,
            1155,
            1156,
            1158,
            1160,
            1161,
            1162,
            1163,
            1164,
            1165,
            1166,
            1167,
            1168,
            1169,
            1170,
            1171,
            1172,
            1173,
            1174,
            1175,
            1176,
            1177,
            1178,
            1179,
            1180,
            1181,
            1182,
            1183,
            1184,
            1185,
            1186,
            1187,
            1189,
            1190)},
 {'auxiliary': {1382: 1925869570,
                1392: 794966339,
                1400: 992088835,
                1403: 1645349731,
                1409: 2029715971,
                1414: 969273859,
                1419: 64637,
                1420: 1567982083,
                1423: 11318,
                1424: 1270280707,
                1426: 15677,
                1427: 216691203,
                1430: 10292,
                1431: 1877664260,
                1434: 30836,
                1435: 1575424515,
                1436: 1588726995,
                1438: 1949478147},
  'flag0': (1419, 1423, 1434),
  'comparisons': (1400, 1403, 1438),
  'cells': (1380,
            1382,
            1383,
            1384,
            1385,
            1386,
            1387,
            1388,
            1389,
            1390,
            1391,
            1392,
            1393,
            1394,
            1395,
            1396,
            1397,
            1398,
            1399,
            1400,
            1401,
            1402,
            1403,
            1404,
            1405,
            1406,
            1407,
            1408,
            1409,
            1410,
            1411,
            1412,
            1413,
            1414,
            1415,
            1416,
            1417,
            1418,
            1419,
            1420,
            1421,
            1422,
            1423,
            1424,
            1425,
            1426,
            1427,
            1428,
            1429,
            1430,
            1431,
            1432,
            1433,
            1434,
            1435,
            1436,
            1437,
            1438)},
 {'auxiliary': {1456: 1522733058,
                1461: 34677,
                1462: 19997,
                1466: 791834707,
                1469: 39550,
                1474: 400700083,
                1477: 377619347,
                1482: 48942,
                1483: 1573511683,
                1487: 64543,
                1488: 718369284,
                1493: 32109,
                1494: 1870610947,
                1497: 6516,
                1498: 1211216387,
                1500: 6405,
                1501: 768672260,
                1505: 2118189572,
                1508: 11566,
                1509: 1261945348,
                1510: 1183979571,
                1512: 627227427},
  'flag0': (1482, 1487, 1493, 1497, 1500),
  'comparisons': (1477, 1512),
  'cells': (1454,
            1456,
            1457,
            1458,
            1459,
            1460,
            1461,
            1462,
            1463,
            1464,
            1465,
            1466,
            1467,
            1468,
            1469,
            1470,
            1471,
            1472,
            1473,
            1474,
            1475,
            1476,
            1477,
            1478,
            1479,
            1480,
            1481,
            1482,
            1483,
            1484,
            1485,
            1486,
            1487,
            1488,
            1489,
            1490,
            1491,
            1492,
            1493,
            1494,
            1495,
            1496,
            1497,
            1498,
            1499,
            1500,
            1501,
            1502,
            1503,
            1504,
            1505,
            1506,
            1507,
            1508,
            1509,
            1510,
            1511,
            1512)})


_RECIPE = {'auxiliary': {1207: 1376966388,
               1215: 62013,
               1216: 1278377892,
               1217: 1992432854,
               1222: 2024955906,
               1228: 1300370502,
               1234: 1875783681,
               1238: 2039665382,
               1242: 412770305,
               1246: 731046054,
               1250: 1514397698,
               1256: 1434614998,
               1260: 2025299969,
               1264: 1852994998,
               1268: 2066358274,
               1272: 1557296294,
               1278: 2011301686,
               1287: 26381,
               1288: 235032596,
               1297: 1179820468,
               1298: 1551004790,
               1299: 18285,
               1303: 1611628546,
               1309: 385008294,
               1315: 1978441729,
               1319: 1343391878,
               1323: 656228354,
               1327: 1076031318,
               1331: 1108652033,
               1337: 1984083078,
               1341: 705003521,
               1345: 1733464422,
               1349: 1113927682,
               1353: 2043834518,
               1359: 851592022,
               1367: 705692163,
               1374: 10359,
               1364: 909004801,
               1447: 15158},
 'flag0': (1447,),
 'comparisons': ()}


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'seed_frame.phi')


def _phis(vm, destinations, sources):
    for destination, source in zip(destinations, sources):
        _phi(vm, destination, source)


def _condition(vm, left, right, destination, *, greater=False):
    _auxiliary(vm, _RECIPE, destination)
    typ = 3 if greater else 7
    first, second = vm._signed_cell(left, typ), vm._signed_cell(right, typ)
    vm._write(destination, int(first > second if greater else first != second),
              4, 'seed_frame.condition')
    return bool(vm.cells.value(destination))


def _advance(vm, source, destination, source_next, value, destination_next, width, state, *, wide=False):
    _address(vm, 3 if width == 4 else 1, source, source_next, 163)
    _load(vm, source, value, width)
    _address(vm, 3 if width == 4 else 1, destination, destination_next, 163)
    _store(vm, value, destination, width, wide=wide)
    state['copied_bytes'] += width


def _copy_four(vm, source, base, state):
    cell = lambda offset: base + offset
    vm.cells.copy_q_clear_owned(base, cell(1))
    _binary(vm, _RECIPE, cell(1), 169, cell(2), 7, 'and')
    _advance(vm, source, base, cell(3), cell(4), cell(5), 1, state)
    vm.cells.copy_q_clear_owned(cell(5), cell(6))
    _binary(vm, _RECIPE, cell(6), 169, cell(7), 7, 'and')
    selected = _condition(vm, cell(7), 145, cell(8))
    if selected:
        _advance(vm, cell(3), cell(5), cell(9), cell(10), cell(11), 1, state,
                 wide=base == 1199)
    _phis(vm, (cell(12), cell(13), cell(14)),
          (311, cell(11), cell(9)) if selected else (149, cell(5), cell(3)))
    vm.cells.copy_q_clear_owned(cell(13), cell(15))
    _binary(vm, _RECIPE, cell(15), 169, cell(16), 7, 'and')
    _condition(vm, cell(16), 145, cell(17))
    _condition(vm, cell(12), 158, cell(18), greater=True)
    _binary(vm, _RECIPE, cell(17), cell(18), cell(19), 98, 'and')
    selected = bool(vm.cells.value(cell(19)))
    if selected:
        _advance(vm, cell(14), cell(13), cell(20), cell(21), cell(22), 1, state,
                 wide=base == 1199)
        _binary(vm, _RECIPE, cell(12), 396, cell(23), 3, 'add')
    _phis(vm, (cell(24), cell(25), cell(26)),
          (cell(23), cell(22), cell(20)) if selected else (cell(12), cell(13), cell(14)))
    vm.cells.copy_q_clear_owned(cell(25), cell(27))
    vm.cells.copy_q_clear_owned(cell(26), cell(28))
    selected = _condition(vm, cell(24), 149, cell(29), greater=True)
    if selected:
        _address(vm, 1, cell(26), cell(30), 172)
        vm.cells.copy_q_clear_owned(cell(30), cell(31))
        _load(vm, cell(28), cell(32), 4)
        _address(vm, 1, cell(25), cell(33), 172)
        vm.cells.copy_q_clear_owned(cell(33), cell(34))
        _store(vm, cell(32), cell(27), 4)
        state['copied_bytes'] += 4
        _binary(vm, _RECIPE, cell(24), 1034, cell(35), 3, 'add')
    _phis(vm, (cell(36), cell(37), cell(38)),
          (cell(35), cell(34), cell(31)) if selected else (cell(24), cell(27), cell(28)))
    for remaining, destination, source_cell, condition, source_next, value, destination_next, following, outputs in (
            (36, 37, 38, 39, 40, 41, 42, 43, (44, 45, 46)),
            (44, 45, 46, 47, 48, 49, 50, 51, (52, 53, 54))):
        selected = _condition(vm, cell(remaining), 149, cell(condition), greater=True)
        if selected:
            _advance(vm, cell(source_cell), cell(destination), cell(source_next), cell(value),
                     cell(destination_next), 4, state)
            _binary(vm, _RECIPE, cell(remaining), 1034, cell(following), 3, 'add')
        _phis(vm, tuple(map(cell, outputs)), tuple(map(cell, (following, destination_next, source_next)
              if selected else (remaining, destination, source_cell))))
    vm.cells.copy_q_clear_owned(cell(53), cell(55))
    vm.cells.copy_q_clear_owned(cell(54), cell(56))
    for remaining, destination, source_cell, condition, source_next, value, destination_next, following, outputs in (
            (52, 55, 56, 57, 58, 59, 60, 61, (62, 63, 64)),
            (62, 63, 64, 65, 66, 67, 68, 69, (70, 71, 72))):
        selected = _condition(vm, cell(remaining), 158, cell(condition), greater=True)
        if selected:
            _advance(vm, cell(source_cell), cell(destination), cell(source_next), cell(value),
                     cell(destination_next), 1, state, wide=base == 1280 and value == 67)
            _binary(vm, _RECIPE, cell(remaining), 396, cell(following), 3, 'add')
        _phis(vm, tuple(map(cell, outputs)), tuple(map(cell, (following, destination_next, source_next)
              if selected else (remaining, destination, source_cell))))
    selected = _condition(vm, cell(70), 158, cell(73), greater=True)
    if selected:
        _advance(vm, cell(72), cell(71), cell(74), cell(75), cell(76), 1, state)
    _phis(vm, (cell(77), cell(78)), (cell(76), cell(74)) if selected else (cell(71), cell(72)))
    if _condition(vm, cell(70), 269, cell(79), greater=True):
        _load(vm, cell(78), cell(80), 1)
        _store(vm, cell(80), cell(77), 1)
        state['copied_bytes'] += 1


def _read_material(vm, number, pointer, captured, index, following, condition, key,
                   value_cells, next_auxiliary, state):
    vm.cells.copy_q_clear_owned(pointer, captured)
    _store(vm, 145, pointer, 8)
    initial = True
    while True:
        _phi(vm, index, 145 if initial else following)
        if not _less(vm, index, 163, condition):
            break
        node, missing = _lookup(vm, 0, index, key, state, recipe=_LOOKUPS[number])
        value_pointer_pointer, value_pointer, byte, target, empty_target = value_cells
        if vm.cells.value(missing):
            _address(vm, 1, captured, empty_target, index)
            _store(vm, 235, empty_target, 1)
        else:
            _address(vm, 79, node, value_pointer_pointer, 145, 311)
            _load(vm, value_pointer_pointer, value_pointer, 8)
            _load(vm, value_pointer, byte, 1)
            _address(vm, 1, captured, target, index)
            _store(vm, byte, target, 1)
        state['material_bytes'] += 1
        vm.auxiliary = (0, next_auxiliary)
        _next(vm, index, 163, following)
        initial = False


def _mix(vm, state):
    _load(vm, 1198, 1361, 1)
    vm.execute_once(10, (3, 1, 1361, 1362))
    initial = True
    while True:
        _phi(vm, 1363, 158 if initial else 1364)
        if not _less(vm, 1363, 502, 1365):
            break
        _binary(vm, _RECIPE, 1363, 1362, 1366, 3, 'xor')
        _binary(vm, _RECIPE, 1366, 867, 1367, 3, 'mul')
        _right(vm, 1367, 375, 1368, 4)
        _binary(vm, _RECIPE, 1367, 1368, 1369, 3, 'xor')
        vm.execute_once(10, (7, 3, 1363, 1370))
        _address(vm, 1, 1199, 1371, 1370)
        _load(vm, 1371, 1372, 1)
        _mask(vm, 1369, 1373, 1)
        _binary(vm, _RECIPE, 1372, 1373, 1374, 1, 'xor')
        _store(vm, 1374, 1371, 1)
        state['mixed_bytes'] += 1
        _binary(vm, _RECIPE, 1363, 269, 1364, 3, 'add')
        initial = False


def prepare_primary_seed_frame(vm):
    vm.primary_seed_frame_state = {'phase': 'lookup41', 'lookups': 0, 'integrity_markers': 0,
                                  'material_bytes': 0, 'copied_bytes': 0, 'mixed_bytes': 0,
                                  'memsets': 0, 'retained_steps': 0}
    state = vm.primary_seed_frame_state
    _read_material(vm, 0, 89, 1123, 1124, 1125, 1126, 1128,
                   (1191, 1192, 1193, 1194, 1195), 821567490, state)
    _load(vm, 89, 1196, 8)
    _mask(vm, 1196, 1197, 1)
    _address(vm, 49, 113, 1198, 145, 145)
    _store(vm, 1197, 1198, 1)
    state['phase'] = 'seed_copy'
    _address(vm, 49, 113, 1199, 145, 163)
    _copy_four(vm, 934, 1199, state)
    state['phase'] = 'nonce_copy'
    _address(vm, 49, 113, 1280, 145, 175)
    _copy_four(vm, 952, 1280, state)
    state['phase'] = 'mix'
    _mix(vm, state)
    _load(vm, 1198, 1375, 1)
    state['phase'] = 'lookup35'
    _read_material(vm, 1, 88, 1376, 1377, 1378, 1379, 1381,
                   (1439, 1440, 1441, 1442, 1443), 966180866, state)
    _load(vm, 88, 1444, 8)
    _mask(vm, 1444, 1445, 1)
    _binary(vm, _RECIPE, 1375, 1445, 1446, 1, 'xor')
    _binary(vm, _RECIPE, 1446, 152, 1447, 1, 'xor')
    _store(vm, 1447, 1198, 1)
    observer = getattr(vm.runtime, '_primary_stage_observer', None)
    if observer is not None:
        observer('local113', vm.memory.read(vm.cells.value(113), 16), None, 9559, 9563)
    _address(vm, 49, 116, 1448, 145, 145)
    _retained(vm, 9571, 209, 206, 1, state)
    state['memsets'] += 1
    state['phase'] = 'lookup42'
    _read_material(vm, 2, 87, 1450, 1451, 1452, 1453, 1455,
                   (1513, 1514, 1515, 1516, 1517), 1510400001, state)
    _load(vm, 87, 1518, 8)
    _mask(vm, 1518, 1519, 1)
    _address(vm, 49, 116, 1520, 145, 145)
    _store(vm, 1519, 1520, 1, wide=True)
    state['phase'] = 'rolling_inputs'
    vm.cells.copy_q_clear_owned(117, 1521)
    vm.cells.copy_q_clear_owned(79, 1522)
    _store(vm, 145, 79, 8)
    vm.cells.copy_q_clear_owned(79, 1523)
    _address(vm, 45, 76, 1524, 145, 145)
    _address(vm, 45, 76, 1525, 145, 145)
    _store(vm, 1526, 1525, 1)
    for index, target, source in ((163, 1527, 1528), (166, 1529, 1530), (169, 1531, 1532)):
        _address(vm, 45, 76, target, 145, index)
        _store(vm, source, target, 1)
    _address(vm, 49, 94, 1533, 145, 145)
    _retained(vm, 10182, 220, 217, 1, state)
    state['memsets'] += 1
    vm.cells.copy_q_clear_owned(77, 1535)
    _store(vm, 1536, 77, 4)
    vm.cells.copy_q_clear_owned(78, 1537)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 10207, 228, 220, False
    state['phase'] = 'complete'
    return True
