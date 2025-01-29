from pathlib import Path

import wake.deployment
from wake.testing import *

from pytypes.core.contracts.common.lib.MinFirstAllocationStrategy import MinFirstAllocationStrategy
from pytypes.core.contracts._0_8_9.StakingRouter import StakingRouter
from pytypes.core.contracts._0_8_9.DepositSecurityModule import DepositSecurityModule
from pytypes.core.contracts._0_8_9.oracle.AccountingOracle import AccountingOracle
from pytypes.core.contracts._0_8_9.sanity_checks.OracleReportSanityChecker import OracleReportSanityChecker, LimitsList


pre_chain = Chain()
post_chain = wake.deployment.Chain()


nor_creation_code = (Path(__file__).parent.parent / "bin" / "NodeOperatorsRegistry.bin").read_text()


@pre_chain.connect(fork="http://localhost:8545@20921268")
@post_chain.connect("http://localhost:8545")
def test_deployment():
    sender = Account("0x1F27e93D9E178b2d8e808110a551A65b7fD9F182", chain=pre_chain)
    st_eth = Address("ae7ab96520de3a18e5e111b5eaab095312d7fe84")
    deposit_contract = Address("0x00000000219ab540356cbb839cbe05303d7705fa")
    staking_router_proxy = Address("fddf38947afb03c621c71b06c9c70bce73f12999")
    locator = Address("C1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb")

    pre_chain.default_tx_account = sender

    min_first_allocation_strategy = MinFirstAllocationStrategy.deploy(chain=pre_chain)
    min_first_allocation_strategy2 = MinFirstAllocationStrategy("0x7e70De6D1877B3711b2bEDa7BA00013C7142d993", chain=post_chain)
    assert min_first_allocation_strategy.code[:-53] == min_first_allocation_strategy2.code[:-53]
    assert min_first_allocation_strategy.address == min_first_allocation_strategy2.address

    staking_router = StakingRouter.deploy(deposit_contract, chain=pre_chain, minFirstAllocationStrategy=min_first_allocation_strategy)
    staking_router2 = StakingRouter("0x89eDa99C0551d4320b56F82DDE8dF2f8D2eF81aA", chain=post_chain)
    assert staking_router.code[:-53] == staking_router2.code[:-53]
    assert staking_router.address == staking_router2.address

    nor = pre_chain.deploy(bytes.fromhex(nor_creation_code.replace("__core/contracts/common/lib/MinFirstAl__", str(min_first_allocation_strategy.address)[2:])))
    nor2 = Account("0x1770044a38402e3CfCa2Fcfa0C84a093c9B42135", chain=post_chain)
    assert nor.code[:-53] == nor2.code[:-53]
    assert nor.address == nor2.address

    dsm = DepositSecurityModule.deploy(st_eth, deposit_contract, staking_router_proxy, 6646, 200, chain=pre_chain)
    dsm2 = DepositSecurityModule("0xfFA96D84dEF2EA035c7AB153D8B991128e3d72fD", chain=post_chain)
    assert dsm.code[:-53] == dsm2.code[:-53]
    assert dsm.address == dsm2.address

    sender.nonce += 2

    accounting_oracle = AccountingOracle.deploy(locator, st_eth, Address("442af784a788a5bd6f42a01ebe9f287a871243fb"), 12, 1606824023, chain=pre_chain)
    accounting_oracle2 = AccountingOracle("0x0e65898527E77210fB0133D00dd4C0E86Dc29bC7", chain=post_chain)
    assert accounting_oracle.code[:-53] == accounting_oracle2.code[:-53]
    assert accounting_oracle.address == accounting_oracle2.address

    limits = LimitsList(
        exitedValidatorsPerDayLimit=9000,
        appearedValidatorsPerDayLimit=43200,
        annualBalanceIncreaseBPLimit=1000,
        simulatedShareRateDeviationBPLimit=50,
        maxValidatorExitRequestsPerReport=600,
        maxItemsPerExtraDataTransaction=8,
        maxNodeOperatorsPerExtraDataItem=24,
        requestTimestampMargin=7680,
        maxPositiveTokenRebase=750000,
        initialSlashingAmountPWei=1000,
        inactivityPenaltiesAmountPWei=101,
        clBalanceOraclesErrorUpperBPLimit=50,
    )
    sanity_checker = OracleReportSanityChecker.deploy(locator, Address("3e40d73eb977dc6a537af587d48316fee66e9c8c"), limits, chain=pre_chain)
    sanity_checker2 = OracleReportSanityChecker("0x6232397ebac4f5772e53285B26c47914E9461E75", chain=post_chain)
    assert sanity_checker.code[:-53] == sanity_checker2.code[:-53]
    assert sanity_checker.address == sanity_checker2.address

    tmp_chain = Chain()
    with tmp_chain.connect(fork="http://localhost:8545@20921275"):
        sanity_checker3 = OracleReportSanityChecker("0x6232397ebac4f5772e53285B26c47914E9461E75", chain=tmp_chain)
        assert sanity_checker3.getOracleReportLimits() == limits
