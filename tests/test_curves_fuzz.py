from bisect import bisect_right
from typing import Dict
from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.csm.src.CSAccounting import CSAccounting
from pytypes.csm.src.interfaces.ILidoLocator import ILidoLocator
from pytypes.csm.src.lib.AssetRecovererLib import AssetRecovererLib
from pytypes.csm.src.lib.proxy.OssifiableProxy import OssifiableProxy

LIDO_LOCATOR = ILidoLocator("0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb")
MIN_BOND_LOCK_RETENTION_PERIOD = 4 * 7 * 24 * 60 * 60  # 4 weeks
MAX_BOND_LOCK_RETENTION_PERIOD = 365 * 24 * 60 * 60  # 1 year


class CurvesFuzzTest(FuzzTest):
    accounting: CSAccounting
    admin: Account
    curves: Dict[int, List[int]]

    def pre_sequence(self) -> None:
        AssetRecovererLib.deploy()

        self.admin = random_account()
        self.max_curve_length = random_int(1, 100)
        self.accounting = CSAccounting(OssifiableProxy.deploy(
            CSAccounting.deploy(
                LIDO_LOCATOR,
                Address(1),
                self.max_curve_length,
                MIN_BOND_LOCK_RETENTION_PERIOD,
                MAX_BOND_LOCK_RETENTION_PERIOD,
            ),
            self.admin,
            b"",
        ))

        curve = [random_int(1, 100) for _ in range(random_int(1, self.max_curve_length))]
        curve = sorted(set(curve))
        self.accounting.initialize(
            curve,
            self.admin,
            Account(1),
            MIN_BOND_LOCK_RETENTION_PERIOD,
            Address(1),
        )
        self.accounting.grantRole(self.accounting.MANAGE_BOND_CURVES_ROLE(), self.admin, from_=self.admin)
        self.curves = {}
        self.curves[0] = curve

    @flow()
    def flow_add_curve(self):
        curve = [random_int(1, 100) for _ in range(random_int(0, self.max_curve_length + 5))]
        sort = random_bool()
        if sort:
            curve.sort()

        with may_revert((CSAccounting.InvalidBondCurveValues, CSAccounting.InvalidBondCurveLength)) as e:
            tx = self.accounting.addBondCurve(curve, from_=self.admin)

        if len(curve) > self.max_curve_length or len(curve) == 0:
            assert e.value == CSAccounting.InvalidBondCurveLength()
        elif 0 in curve or sorted(curve) != curve or len(set(curve)) != len(curve):
            assert e.value == CSAccounting.InvalidBondCurveValues()
        else:
            assert e.value is None
            self.curves[tx.return_value] = curve

    @flow()
    def flow_update_curve(self):
        curve_id = random.choice(list(self.curves.keys()) + [random_int(1, 1000) for _ in range(5)])
        curve = [random_int(1, 100) for _ in range(random_int(0, self.max_curve_length))]
        sort = random_bool()
        if sort:
            curve.sort()

        with may_revert((CSAccounting.InvalidBondCurveValues, CSAccounting.InvalidBondCurveLength, CSAccounting.InvalidBondCurveId)) as e:
            tx = self.accounting.updateBondCurve(curve_id, curve, from_=self.admin)

        if curve_id not in self.curves:
            assert e.value == CSAccounting.InvalidBondCurveId()
        elif len(curve) > self.max_curve_length or len(curve) == 0:
            assert e.value == CSAccounting.InvalidBondCurveLength()
        elif 0 in curve or sorted(curve) != curve or len(set(curve)) != len(curve):
            assert e.value == CSAccounting.InvalidBondCurveValues()
        else:
            assert e.value is None
            self.curves[curve_id] = curve

    @invariant()
    def invariant(self):
        for _ in range(100):
            curve_id = random.choice(list(self.curves.keys()) + [random_int(1, 1000) for _ in range(5)])
            curve = self.curves[curve_id] if curve_id in self.curves else [10000]
            step = curve[0] if len(curve) == 1 else curve[-1] - curve[-2]

            for _ in range(50):
                bond = random_int(0, curve[-1] * 2)

                if bond > curve[-1]:
                    expected = len(curve) + (bond - curve[-1]) // step
                else:
                    expected = bisect_right(curve, bond)

                with may_revert(CSAccounting.InvalidBondCurveId) as e:
                    assert self.accounting.getKeysCountByBondAmount(bond, curve_id) == expected

                assert (e.value is None) == (curve_id in self.curves)

            for _ in range(50):
                keys = random_int(0, len(curve) * 2)

                if keys == 0:
                    expected = 0
                elif keys >= len(curve):
                    expected = curve[-1] + (keys - len(curve)) * step
                else:
                    expected = curve[keys - 1]

                with may_revert(CSAccounting.InvalidBondCurveId) as e:
                    assert self.accounting.getBondAmountByKeysCount(keys, curve_id) == expected

                assert (e.value is None) == (curve_id in self.curves)


@chain.connect(fork="http://localhost:8545")
def test_curves_fuzz():
    CurvesFuzzTest().run(100, 10_000)
