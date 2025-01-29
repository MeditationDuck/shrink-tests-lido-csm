from wake.testing import Account, Address
from pytypes.core.contracts._0_6_11.deposit_contract import IDepositContract
from pytypes.core.contracts._0_8_9.Burner import Burner
from pytypes.core.contracts._0_8_9.DepositSecurityModule import DepositSecurityModule
from pytypes.core.contracts._0_8_9.LidoLocator import LidoLocator
from pytypes.core.contracts._0_8_9.OracleDaemonConfig import OracleDaemonConfig
from pytypes.core.contracts._0_8_9.StakingRouter import StakingRouter
from pytypes.core.contracts._0_8_9.WithdrawalQueue import WithdrawalQueue
from pytypes.core.contracts._0_8_9.WithdrawalQueueERC721 import WithdrawalQueueERC721

from pytypes.core.contracts._0_8_9.WithdrawalVault import WithdrawalVault
from pytypes.core.contracts._0_8_9.oracle.AccountingOracle import AccountingOracle

from pytypes.core.contracts._0_8_9.oracle.ValidatorsExitBusOracle import ValidatorsExitBusOracle
from pytypes.core.contracts._0_8_9.sanity_checks.OracleReportSanityChecker import OracleReportSanityChecker
from pytypes.core.contracts.common.interfaces.ILidoLocator import ILidoLocator
from pytypes.tests.migrated_contracts.LidoMigrated import LidoMigrated
from pytypes.tests.migrated_contracts.aragon.os.acl.ACL import ACL
from pytypes.tests.migrated_contracts.aragon.os.kernel.Kernel import Kernel
from pytypes.core.contracts._0_8_9.oracle.HashConsensus import HashConsensus
from pytypes.core.contracts._0_8_9.oracle.ValidatorsExitBusOracle import ValidatorsExitBusOracle
from pytypes.core.contracts._0_6_12.WstETH import WstETH



LIDO_MAINNET_DEPLOYER_EOA = Address("0x8ea83ad72396f1e0cd2f8e72b1461db8eb6af7b5")


DEPOSIT_CONTRACT = IDepositContract("0x00000000219ab540356cBB839Cbe05303d7705Fa")
LIDO = LidoMigrated("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
LIDO_LOCATOR = ILidoLocator("0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb")
LIDO_DAO = Kernel("0xb8FFC3Cd6e7Cf5a098A1c92F48009765B24088Dc")
ARAGON_ACL = ACL("0x9895f0f17cc1d1891b6f18ee0b483b6f221b37bb")
BURNER = Burner("0xD15a672319Cf0352560eE76d9e89eAB0889046D3")
WITHDRAWAL_VAULT = WithdrawalVault("0xb9d7934878b5fb9610b3fe8a5e441e8fad7e293f")
WITHDRAWAL_QUEUE = WithdrawalQueueERC721("0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1")
ORACLE_DAEMON_CONFIG = OracleDaemonConfig("0xbf05A929c3D7885a6aeAd833a992dA6E5ac23b09")
EL_REWARDS_VAULT = Account("0x388C818CA8B9251b393131C08a736A67ccB19297")
ACCOUNTING_ORACLE = AccountingOracle("0x852deD011285fe67063a08005c71a85690503Cee")
DSM = DepositSecurityModule("0xC77F8768774E1c9244BEed705C4354f2113CFc09")
LEGACY_ORACLE = Account("0x442af784A788A5bd6F42A01Ebe9F287a871243fb")
ORACLE_REPORT_SANITY_CHECKER = OracleReportSanityChecker("0x9305c1Dbfe22c12c66339184C0025d7006f0f1cC")
STAKING_ROUTER = StakingRouter("0xFdDf38947aFB03C621C71b06C9C70bce73f12999")
VALIDATOR_EXIT_BUS_ORACLE = ValidatorsExitBusOracle("0x0De4Ea0184c2ad0BacA7183356Aea5B8d5Bf5c6e")
TREASURY = Account("0x0000000000000000000000000000000000000042")
ARAGON_VOTING = Account("0x2e59A20f205bB85a89C53f1936454680651E618e")
WST_ETH = WstETH("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0")

FORK_CONFIG = LidoLocator.Config(
    accountingOracle=ACCOUNTING_ORACLE,
    depositSecurityModule=DSM,
    elRewardsVault=EL_REWARDS_VAULT,
    legacyOracle=LEGACY_ORACLE,
    lido=LIDO,
    oracleReportSanityChecker=ORACLE_REPORT_SANITY_CHECKER,
    postTokenRebaseReceiver=LEGACY_ORACLE,
    burner=BURNER,
    stakingRouter=STAKING_ROUTER,
    treasury=TREASURY,
    validatorsExitBusOracle=VALIDATOR_EXIT_BUS_ORACLE,
    withdrawalQueue=WITHDRAWAL_QUEUE,
    withdrawalVault=WITHDRAWAL_VAULT,
    oracleDaemonConfig=ORACLE_DAEMON_CONFIG
)

# https://etherscan.io/address/0xD624B08C83bAECF0807Dd2c6880C3154a5F0B288#readContract#F7
SLOTS_PER_EPOCH = 32
SECONDS_PER_SLOT = 12
GENESIS_TIME = 1606824023
# https://etherscan.io/address/0xD624B08C83bAECF0807Dd2c6880C3154a5F0B288#readContract#F12
# 225 makes 1 frame = 1 day
EPOCHS_PER_FRAME = 225
FAST_LANE_LENGTH_SLOTS = 100
CONSENSUS_VERSION = 1

CONSENSUS_MEMBERS_NUM = 5
CONSENSUS_QUORUM = 3

INITIAL_VALIDATORS_COUNT = 500
INITIAL_FAST_LANE_LENGTH_SLOTS=0


DEADLINE_SLOT_OFFSET = 0
