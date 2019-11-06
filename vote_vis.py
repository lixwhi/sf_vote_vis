import csv
from web3 import Web3
import json
import time
import configparser
import collections
import sys
import argparse
import math
from datetime import datetime
import etherscan
from Crypto.Hash import keccak
import rlp
import pickle
from sha3 import keccak_256
from mpl_toolkits.mplot3d import Axes3D
import mpl_toolkits.mplot3d.art3d as art3d
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, Rectangle, PathPatch
from matplotlib.text import TextPath
from matplotlib.transforms import Affine2D
from matplotlib import rc
# parser, spell fetching, and config.ini all from:
# https://github.com/jernejml/mkr_voting

rc('font',size=7)
rc('font',family='serif')
rc('axes',labelsize=12)
rc('grid', color=(242 / 255, 242 / 255, 242 / 255, 242 / 255))
rc('grid', linestyle='-')
rc('grid', linewidth=0.5)
rc('axes', edgecolor=(202 / 255, 202 / 255, 202 / 255, 1))
rc('xtick', color=(102 / 255, 102 / 255, 102 / 255, 1))
rc('ytick', color=(102 / 255, 102 / 255, 102 / 255, 1))
rc('xtick', labelsize='large')
rc('ytick', labelsize='large')
rc('figure', figsize= (16, 9))
rc('figure', dpi=250)
#rc('figure', autolayout=True)
#rc('ztick', color=(202 / 255, 202 / 255, 202 / 255, 1))

START_BLOCK = 7707853
END_BLOCK = 8848544
voter_filenam = 'voters_blocks_{0}-{1}.csv'.format(START_BLOCK, END_BLOCK)

blocks_per_frame = 1000

CONFIG_FILE = 'config.ini'
config = configparser.ConfigParser()
config.read(CONFIG_FILE)
args = None
web3 = None
ETH_SCALE = 1000000000000000000
CHIEF = '0x9eF05f7F6deB616fd37aC3c959a2dDD25A54E4F5'
MINTER = '0x496C67A4CEd9C453A60F3166AB4B329870c8E355'
CHIEF_ABI = json.loads('[{"constant":true,"inputs":[],"name":"IOU","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"who","type":"address"}],"name":"getUserRoles","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"owner_","type":"address"}],"name":"setOwner","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"GOV","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"code","type":"address"},{"name":"sig","type":"bytes4"}],"name":"getCapabilityRoles","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"code","type":"address"},{"name":"sig","type":"bytes4"}],"name":"isCapabilityPublic","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"MAX_YAYS","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"whom","type":"address"}],"name":"lift","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"yays","type":"address[]"}],"name":"etch","outputs":[{"name":"slate","type":"bytes32"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"approvals","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"who","type":"address"},{"name":"role","type":"uint8"},{"name":"enabled","type":"bool"}],"name":"setUserRole","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"authority_","type":"address"}],"name":"setAuthority","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"role","type":"uint8"},{"name":"code","type":"address"},{"name":"sig","type":"bytes4"},{"name":"enabled","type":"bool"}],"name":"setRoleCapability","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"who","type":"address"},{"name":"role","type":"uint8"}],"name":"hasUserRole","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"slate","type":"bytes32"}],"name":"vote","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"caller","type":"address"},{"name":"code","type":"address"},{"name":"sig","type":"bytes4"}],"name":"canCall","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"authority","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"bytes32"},{"name":"","type":"uint256"}],"name":"slates","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"code","type":"address"},{"name":"sig","type":"bytes4"},{"name":"enabled","type":"bool"}],"name":"setPublicCapability","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"who","type":"address"},{"name":"enabled","type":"bool"}],"name":"setRootUser","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"votes","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"wad","type":"uint256"}],"name":"free","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"wad","type":"uint256"}],"name":"lock","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"yays","type":"address[]"}],"name":"vote","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"who","type":"address"}],"name":"isUserRoot","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"deposits","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"hat","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[{"name":"GOV","type":"address"},{"name":"IOU","type":"address"},{"name":"MAX_YAYS","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"name":"slate","type":"bytes32"}],"name":"Etch","type":"event"},{"anonymous":true,"inputs":[{"indexed":true,"name":"sig","type":"bytes4"},{"indexed":true,"name":"guy","type":"address"},{"indexed":true,"name":"foo","type":"bytes32"},{"indexed":true,"name":"bar","type":"bytes32"},{"indexed":false,"name":"wad","type":"uint256"},{"indexed":false,"name":"fax","type":"bytes"}],"name":"LogNote","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"authority","type":"address"}],"name":"LogSetAuthority","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"}],"name":"LogSetOwner","type":"event"}]')
MINTER_ABI = json.loads('[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"stop","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"guy","type":"address"},{"name":"wad","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"owner_","type":"address"}],"name":"setOwner","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"src","type":"address"},{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"guy","type":"address"},{"name":"wad","type":"uint256"}],"name":"mint","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"wad","type":"uint256"}],"name":"burn","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"name_","type":"bytes32"}],"name":"setName","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"src","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"stopped","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"authority_","type":"address"}],"name":"setAuthority","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"guy","type":"address"},{"name":"wad","type":"uint256"}],"name":"burn","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"wad","type":"uint256"}],"name":"mint","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"push","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"src","type":"address"},{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"move","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"start","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"authority","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"guy","type":"address"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"src","type":"address"},{"name":"guy","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"src","type":"address"},{"name":"wad","type":"uint256"}],"name":"pull","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[{"name":"symbol_","type":"bytes32"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"name":"guy","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Mint","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"guy","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Burn","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"authority","type":"address"}],"name":"LogSetAuthority","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"}],"name":"LogSetOwner","type":"event"},{"anonymous":true,"inputs":[{"indexed":true,"name":"sig","type":"bytes4"},{"indexed":true,"name":"guy","type":"address"},{"indexed":true,"name":"foo","type":"bytes32"},{"indexed":true,"name":"bar","type":"bytes32"},{"indexed":false,"name":"wad","type":"uint256"},{"indexed":false,"name":"fax","type":"bytes"}],"name":"LogNote","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"guy","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"dst","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Transfer","type":"event"}]')
SLATE_ABI = json.loads('[{"constant":true,"inputs":[],"name":"data","outputs":[{"name":"","type":"bytes"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"cast","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"done","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"mana","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"whom","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[{"name":"whom_","type":"address"},{"name":"mana_","type":"uint256"},{"name":"data_","type":"bytes"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":true,"inputs":[{"indexed":true,"name":"sig","type":"bytes4"},{"indexed":true,"name":"guy","type":"address"},{"indexed":true,"name":"foo","type":"bytes32"},{"indexed":true,"name":"bar","type":"bytes32"},{"indexed":false,"name":"wad","type":"uint256"},{"indexed":false,"name":"fax","type":"bytes"}],"name":"LogNote","type":"event"}]')
SPELL_DB = 'spells.obj'
INTERACTION_DB = 'interactions.obj'
VOTE_TALLY_DB = 'vote_tally.obj'


class Spell:
	def __init__(self, address, rate, created, blocknum, deployer, label, tx):
		self.address = address
		self.rate = rate
		self.created = created
		self.blocknum = blocknum
		self.deployer = deployer
		self.label = label
		self.tx = tx
		self.casted_on = 0
	def setCasted_on(self, casted_on):
		self.casted_on = casted_on


	def created_at(self):
		return datetime.utcfromtimestamp(self.created).strftime('%Y-%m-%d %H:%M:%S')

	def display_spell(self):
		print(str(self.address) + " spell fee rate  " + str(self.rate) + " created at: " + self.created_at() + " in block: " + str(self.blocknum) + ' casted in: ' + str(self.casted_on))

class Interaction:
	def __init__(self, user_address, spell_address, mkr_locked, block, tx_hash):
		self.user_address = user_address
		self.spell_address = spell_address
		self.mkr_locked = mkr_locked
		self.block = block
		self.tx_hash = tx_hash
		self.voter_number = 0
		
	def setVoter_number(self, vnum):
		self.voter_number = vnum

	def display_interaction(self):
		print(str(self.user_address) + " voted for " + str(self.spell_address) + " in block: " + str(self.block) + " with " + str(self.mkr_locked))

class Dot:
	def __init__(self, x, y, z, size):
		self.x = x
		self.y = y
		self.z = z
		self.size = size

class Pframe:
	def __init__(self, blocknum, spell_dict, hatter, prev_cast):
		self.blocknum = blocknum
		self.spell_dict = spell_dict
		self.hatter = hatter
		self.prev_cast = prev_cast
	def display_votes(self):
		print('\nin block {0} {1} had the hat and {2} was the previous cast spell'.format(self.blocknum, self.hatter, self.prev_cast))
		for i in self.spell_dict:
			print('{0} has {1} votes'.format(i, self.spell_dict[i]))



def get_slates(tx):
	setek = set()
	for t in tx:
		if t.get('input').split('0x', 1)[1][:8] == '3c278bd5':
			setek.add('0x' + t.get('input')[-40:])
	for s in setek:
		print(s)
	pass

def text3d(ax, xyz, s, zdir="z", size=None, angle=0, usetex=False, **kwargs):
    '''
    Plots the string 's' on the axes 'ax', with position 'xyz', size 'size',
    and rotation angle 'angle'.  'zdir' gives the axis which is to be treated
    as the third dimension.  usetex is a boolean indicating whether the string
    should be interpreted as latex or not.  Any additional keyword arguments
    are passed on to transform_path.

    Note: zdir affects the interpretation of xyz.
    '''
    x, y, z = xyz
    if zdir == "y":
        xy1, z1 = (x, z), y
    elif zdir == "x":
        xy1, z1 = (y, z), x
    else:
        xy1, z1 = (x, y), z

    text_path = TextPath((0, 0), s, size=size, usetex=usetex)
    trans = Affine2D().rotate(angle).translate(xy1[0], xy1[1])

    p1 = PathPatch(trans.transform_path(text_path), **kwargs)
    ax.add_patch(p1)
    art3d.pathpatch_2d_to_3d(p1, z=z1, zdir=zdir)


def sha3(seed):
	return keccak.new(digest_bits=256, data=seed).digest()


def testing():
	pass

def list_spells():
	try:
		with (open(SPELL_DB, "rb")) as openfile:
			while True:
				try:
					return pickle.load(openfile)
				except EOFError:
					break
	except FileNotFoundError:
		print("\nFile " + SPELL_DB + " does not exist. Run 'update_spells' command.\n")
		sys.exit(-1)

def list_votes():
	try:
		with (open(VOTE_TALLY_DB, "rb")) as openfile:
			while True:
				try:
					return pickle.load(openfile)
				except EOFError:
					break
	except FileNotFoundError:
		print("\nFile " + VOTE_TALLY_DB + " does not exist. Run 'get_votes_per_frame' command.\n")
		sys.exit(-1)

def list_interactions():
	try:
		with (open(INTERACTION_DB, "rb")) as openfile:
			while True:
				try:
					return pickle.load(openfile)
				except EOFError:
					break
	except FileNotFoundError:
		print("\nFile " + SPELL_DB + " does not exist. Run 'get_interactions' command.\n")
		sys.exit(-1)

def parse_spell(name, address, txs, spell_list):
	print("Checking deployer '" + name + "' at address: ", address)
	spell_l = spell_list.copy()
	for t in txs:
		if t.get('input').split('0x', 1)[1][:44] == '608060405234801561001057600080fd5b5060405161':
			if t.get('is_error') is True:
				continue
			fr = t.get('from')
			if len(fr) in (42, 50) and fr[:2] == '0x':
				sender = bytes.fromhex(fr[2:])
			else:
				sys.exit(-1)
			nonce = t.get('nonce')
			s = '0x' + keccak_256(rlp.encode([sender, nonce])).hexdigest()[-40:]
			current_spell_contract = web3.eth.contract(address=web3.toChecksumAddress(s), abi=SLATE_ABI)
			fee_per_sec = web3.toInt(hexstr=web3.toHex(current_spell_contract.functions.data().call())[10:74].lstrip(
				'0')) / 1000000000000000000000000000
			fee_apr = 100
			for k in range(365*24*60*60):
				fee_apr = fee_apr * fee_per_sec
			fee_apr = round(fee_apr - 100, 1)
			tx_rec = web3.eth.getTransactionReceipt(t.get('hash'))
			blocknu = tx_rec['blockNumber']
			spell_l.append(Spell(s, fee_apr, t.get('timestamp'), blocknu, address, name, t.get('hash')))
	return spell_l

def find_when_cast(txs):
	CAST_INPUT = '0x96d373e5'
	block_caste = 0
	for t in txs:
		if((t['input'] == CAST_INPUT) and (t['tx_receipt_status'] == True)):
			block_caste = t['block_number']
	return block_caste


def get_spells():
	spell_list = []
	es = etherscan.Client(api_key=config['ETHERSCAN_API']['key'], cache_expire_after=5)
	for k, v in list(config.items('DEPLOYER_ADDRESSES')):
		txs = es.get_transactions_by_address(v, limit=10000)
		spell_list = parse_spell(k, v, txs, spell_list)

	for i in spell_list:
		try:
			txs = es.get_transactions_by_address(i.address, limit=1000)
		except:
			continue
		cast_block = find_when_cast(txs)
		i.setCasted_on(cast_block)

	return spell_list



def modify_provider_address():
	provider = config['PROVIDER']['http']
	if provider == 'https://mainnet.infura.io/v3/87a12d5e368148be95f73278d6067b16':
		sys.exit("Add your own http provider to the config.ini file! \n Reference: https://web3py.readthedocs.io/en/stable/providers.html#httpprovider \n Use http = <address> in section PROVIDER")
	private_key = config['ACCOUNT']['key']
	if private_key == '0b22c7bffca906956cf8458a0725d89d0a58c5f7f7d8c20f19caa3b0afeb5ea2':
		sys.exit('WARNING! Add private key of your own ethereum account. Use only account with tiny amount of value!!!')
	etherscan_api_key = config['ETHERSCAN_API']['key']
	if etherscan_api_key == 'BXY5F3KX7CYSHER6BTQBD33UYW45M6HYFN':
		sys.exit('Add your own etherscan api key to the config.ini file. \n Register at https://etherscan.io/register. Use key = <key value> in section ETHERSCAN_API')


def connect_ws():
	web3 = Web3(Web3.WebsocketProvider(config['PROVIDER']['wss']))
	if not web3.isConnected():
		sys.exit("Web3 is not connected.")
	return web3

def connect():
	web3 = Web3(Web3.HTTPProvider(config['PROVIDER']['http']))
	if not web3.isConnected():
		sys.exit("Web3 via websocket is not connected.")
	return web3


def label(s):
    tmp = str(s[:2] + '.' + s[2:])
    sep = '_'
    return tmp.split(sep, 1)[0]

def get_voters():
	minter_contract = web3.eth.contract(address=MINTER, abi=MINTER_ABI)
	VOTERS_AT_A_TIME = 100000
	latest_block = web3.eth.blockNumber
	loops = math.floor((END_BLOCK - START_BLOCK) / VOTERS_AT_A_TIME)

	voters = []
	for i in range(0, loops + 1):
		start_b = START_BLOCK + (i * VOTERS_AT_A_TIME)
		print(start_b)
		end_b = start_b + VOTERS_AT_A_TIME
		if(end_b > latest_block):
			end_b = latest_block
		loop_minters = []
		loop_minters = minter_contract.events.Mint.createFilter(fromBlock=start_b, toBlock=end_b).get_all_entries()
		for k in loop_minters:
			if(k['args']['guy'] not in voters):
				voters.append(k['args']['guy'])

	return voters

def get_interactions(fname):
	chief_contract = web3.eth.contract(address=CHIEF, abi=CHIEF_ABI)
	#LOCK = 'dd467064'
	VOTE = 'ed081329'
	#FREE = 'd8ccd0f3'
	#MINT_TOPIC = '0x0f6798a560793a54c3bcfe86a93cde1e73087d944c0ea20544137d4121396885'
	#BURN_TOPIC = '0xcc16f5dbb4873280815c1ee09dbd06736cffcc184412cf7a71a0fdb75d397ca5'
	VOTE_TOPIC = '0xed08132900000000000000000000000000000000000000000000000000000000'

	spells = []
	list = list_spells()
	list.sort(key=lambda x: x.created)
	for s in list:
		spells.append(s.address)

	voters = []
	with open(fname) as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			voters.append(row[0])

	interactions = []
	es = etherscan.Client(api_key=config['ETHERSCAN_API']['key'], cache_expire_after=5)
	for i in voters:
		txs = es.get_transactions_by_address(i, limit=5000)
		print('\ntxs for {0}'.format(i))
		time.sleep(1)

		votes_locked = 0
		for k in txs:
			input_chars = str(k['input'][2:10])
			if((k['tx_receipt_status'] == False) or (k['block_number'] > END_BLOCK) or (k['block_number'] < START_BLOCK)):
				continue
			
			if(input_chars == VOTE):
				tx_rec = web3.eth.getTransactionReceipt(k['hash'])
				#print('hash: {0}'.format(k['hash']))
				#print('length k input: {0}'.format(len(k['input'])))
				for j in range(0, len(tx_rec['logs'])):
					if((web3.toHex(bytes(tx_rec['logs'][j]['topics'][0])) == VOTE_TOPIC) and (len(k['input']) == 202)):
						slate_voted_for = '0x' + str(tx_rec['logs'][j]['data'][354:394])
						if(slate_voted_for in spells):
							amt_mkr = chief_contract.functions.deposits(i).call(block_identifier=tx_rec['blockNumber']) / ETH_SCALE
							if (amt_mkr != 0):
								interactions.append(Interaction(i, slate_voted_for, amt_mkr, tx_rec['blockNumber'], k['hash']))
								print('spell voted for: {0} with {1} MKR in block {2}'.format(slate_voted_for, amt_mkr, tx_rec['blockNumber']))
						break

	return interactions



def get_vote_frames(spel):
	chief_contract = web3.eth.contract(address=CHIEF, abi=CHIEF_ABI)
	num_frames = math.floor((END_BLOCK - START_BLOCK) / blocks_per_frame) + 1
	frames = []
	prev_cast = ''
	for i in range(0, num_frames):
		current_bn = ((i + 1) * blocks_per_frame) + START_BLOCK - 1
		print('getting block {0}'.format(current_bn))
		spell_votes = {}
		hat = ''
		for k in spel:
			if ((k.blocknum >= START_BLOCK) and (k.blocknum <= END_BLOCK) and (k.blocknum < current_bn)):
				vo = 0
				try:
					vo = chief_contract.functions.approvals(web3.toChecksumAddress(k.address)).call(block_identifier=current_bn) / ETH_SCALE
				except:
					vo = 0
				spell_votes[k.address] = vo

		try:
			hat = chief_contract.functions.hat().call(block_identifier=current_bn)
			hat = hat.lower()
		except:
			hat = ''
		prev_cast = find_latest_cast(current_bn, spel)
		frames.append(Pframe(current_bn, spell_votes, hat, prev_cast))

	return frames

def find_latest_cast(current_bn, spells):
	cast = []
	for s in spells:
		if(s.casted_on != 0):
			cast.append(s.casted_on)
	cast.reverse()
	the_one = -1
	for c in cast:
		if(c <= current_bn):
			the_one = c
			break
	cas = ''
	for s in spells:
		if(the_one == s.casted_on):
			cas = s.address
	return cas

def make_sf_dict():
	spells = list_spells()
	sf_dict = {}
	for i in spells:
		sf_dict[i.address] = i.rate
	return sf_dict

def make_block_dict():
	spells = list_spells()
	block_dict = {}
	for i in spells:
		block_dict[i.address] = i.blocknum
	return block_dict

def assign_voter_number(inte):
	interact = inte.copy()
	interact.sort(key=lambda x: x.block)
	has_vnum = []
	vnum_dict = {}
	current_vnum = 1
	for i in interact:
		if(i.user_address not in has_vnum):
			i.setVoter_number(current_vnum)
			vnum_dict[i.user_address] = current_vnum
			current_vnum += 1
			has_vnum.append(i.user_address)
		else:
			i.setVoter_number(vnum_dict[i.user_address])
	return interact

def remove_old_dot(dd, vnum):
	ddot = dd.copy()
	if (len(ddot) >= 3):
		for i in range(0, len(ddot) - 1):
			if(ddot[i].x == vnum):
				ddot.pop(i)
				break
	return ddot




def print_frames(interact, frame):

	vot = []
	with open(voter_filenam) as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			vot.append(row[0])
	num_voters = len(vot)
	

	# plt.show()
	spellz = list_spells()
	sf_dict = make_sf_dict()
	block_dict = make_block_dict()
	inters = assign_voter_number(interact)
	inters.sort(key=lambda x: x.block)

	

	dots = []
	frame_count = 0
	last_frame = len(frame) - 1
	hold_last_frames = 48
	START_ELEV = 20
	END_ELEV = 20
	START_AZIM = -20
	END_AZIM = 20
	del_elev = (END_ELEV - START_ELEV) / len(frame)
	del_azim = (END_AZIM - START_AZIM) / len(frame)
	prev_del_elev = 0
	prev_del_azim = 0
	png_output_filename = 'vote_frame'
	RECT_WIDTH = 15000
	SF_CIRC_SIZE = 0.3
	LIGHTEST_COLOR = (227 / 255, 253 / 255, 253 / 255, 255 / 255)
	DOT_COLOR = (203 / 255, 241 / 255, 245 / 255, 68 / 255)
	RECT_COLOR = (166 / 255, 227 / 255, 233 / 255, 255 / 255)
	CAST_COLOR = (113 / 255, 201 / 255, 206 / 255, 255 / 255)

	X_MIN = 0
	X_MAX = 100000
	Y_MIN = START_BLOCK - 50000
	Y_MAX = END_BLOCK + 50000
	Z_MIN = 0
	Z_MAX = 24

	delta_vid = (X_MAX - X_MIN) / (num_voters * 0.95)




	for i in frame:
		fig = plt.figure()
		ax = fig.add_subplot(111, projection='3d')
		ax.set_title('Maker Stability Fee Voting (May 6, 2019 - November 1, 2019)', color=(102 / 255, 102 / 255, 102 / 255, 1), fontsize=15)
		ax.view_init(elev=START_ELEV + prev_del_elev, azim=START_AZIM + prev_del_azim)
		prev_del_elev += del_elev
		prev_del_azim += del_azim
		ax.xaxis.pane.fill = False
		ax.yaxis.pane.fill = False
		ax.zaxis.pane.fill = False
		# ax.xaxis.pane.set_edgecolor((1.0, 1.0, 1.0, 0.0))
		# ax.yaxis.pane.set_edgecolor((1.0, 1.0, 1.0, 0.0))
		# ax.zaxis.pane.set_edgecolor((1.0, 1.0, 1.0, 0.0))
		
		[t.set_va('center') for t in ax.get_yticklabels()]
		[t.set_ha('left') for t in ax.get_yticklabels()]
		[t.set_va('center') for t in ax.get_xticklabels()]
		[t.set_ha('center') for t in ax.get_xticklabels()]
		[t.set_va('center') for t in ax.get_zticklabels()]
		[t.set_ha('left') for t in ax.get_zticklabels()]
		ax.xaxis._axinfo['tick']['inward_factor'] = 0
		ax.xaxis._axinfo['tick']['outward_factor'] = 0.2
		ax.yaxis._axinfo['tick']['inward_factor'] = 0
		ax.yaxis._axinfo['tick']['outward_factor'] = 0.2
		ax.zaxis._axinfo['tick']['inward_factor'] = 0
		ax.zaxis._axinfo['tick']['outward_factor'] = 0.2
		ax.set_xlabel('Votes', color=(102 / 255, 102 / 255, 102 / 255, 1))
		ax.set_ylabel('Blocks', color=(102 / 255, 102 / 255, 102 / 255, 1))
		ax.set_zlabel('Stability Fee (%)', color=(102 / 255, 102 / 255, 102 / 255, 1))
		ax.xaxis.set_rotate_label(True)
		ax.yaxis.set_rotate_label(False)
		ax.zaxis.set_rotate_label(True)
		plt.grid(which="minor", color="r", linestyle='-', linewidth=3)


		first_b = i.blocknum
		last_b = first_b + blocks_per_frame
		# this part updates the location of votes per frame
		for k in inters:
			if((k.block >= first_b) and (k.block < last_b)):
				dots.append(Dot(k.voter_number, block_dict[k.spell_address], sf_dict[k.spell_address], k.mkr_locked))
				dots = remove_old_dot(dots, k.voter_number)

		# this part plots the total tally 2d rectangles if the spell was deployed within block range
		for k in spellz:
			if ((k.blocknum >= START_BLOCK) and (k.blocknum <= END_BLOCK)):
				if(i.prev_cast == k.address):
					sp = Rectangle((0, block_dict[k.address]), i.spell_dict[k.address], RECT_WIDTH, color=CAST_COLOR)
				else:
					sp = Rectangle((0, block_dict[k.address]), i.spell_dict[k.address], RECT_WIDTH, color=RECT_COLOR)
				ax.add_patch(sp)
				art3d.pathpatch_2d_to_3d(sp, z=0, zdir='z')

		# this part plots the updated dots
		for k in dots:
			if((k.y > START_BLOCK) and (k.y < END_BLOCK)):
				ax.scatter(k.x * delta_vid, k.y, k.z, s=math.sqrt(k.size) * 5, color=DOT_COLOR, linewidth=0.3, edgecolors=CAST_COLOR)
		
		# timeline stuff
		time_line = Rectangle((97000, START_BLOCK), 1000, blocks_per_frame * frame_count, color=LIGHTEST_COLOR)
		ax.add_patch(time_line)
		art3d.pathpatch_2d_to_3d(time_line, z=0, zdir='z')

		# guideline for spells
		xx1 = []
		xx2 = []
		yy = []
		zz = []
		
		for k in spellz:
			if ((k.blocknum >= START_BLOCK) and (k.blocknum <= END_BLOCK)):
				xx1.append(0)
				xx2.append(95000)
				yy.append(k.blocknum)
				zz.append(k.rate)
				circ = Circle((k.blocknum, k.rate), SF_CIRC_SIZE, color=CAST_COLOR)
				ax.add_patch(circ)
				art3d.pathpatch_2d_to_3d(circ, z=0, zdir='x')

		for a,b,c,d in zip(xx1, xx2, yy, zz):
			ax.plot([a, b], [c,c], [d,d], color=RECT_COLOR, linewidth=0.4)




		ax.set_xlim(X_MIN, X_MAX)
		ax.set_ylim(Y_MIN, Y_MAX)
		ax.set_zlim(Z_MIN, Z_MAX)
		if (frame_count == last_frame):
			for ff in range(0, hold_last_frames):
				print('saving frame {0}-{1}'.format(frame_count, np.random.rand(5)))
				fig.savefig(png_output_filename + str(frame_count).zfill(5) + '.png')
				frame_count += 1
			fig.clf()
			plt.clf()
			plt.close()
			sys.exit(0)



		print('saving frame {0}-{1}'.format(frame_count, np.random.rand(5)))
		fig.savefig(png_output_filename + str(frame_count).zfill(5) + '.png')
		frame_count += 1
		fig.clf()
		plt.clf()
		plt.close()


		
		# print('\nframe: {0}'.format(i))
		# for j in range(0, len(dots)):
		# 	dots.sort(key=lambda q: q.x)
		# 	print('{0} {1} {2} {3}'.format(dots[j].x, dots[j].y, dots[j].z, dots[j].size))
	










def main():
	# arg parsing
	parser = argparse.ArgumentParser(
		description='make a voter gif')
	parser.add_argument('--testing', action='store_true', dest='test',
						help='temp testing loop, remove later')
	parser.add_argument('--ignore', action='store_true', dest='check',
						help='ignore config.ini modify check')
	parser.add_argument('--update_spells', action='store_true', dest='update_spells',
						help='retrieve deployed from deployer addresses and serialize them to the file ' + SPELL_DB)
	parser.add_argument('--spells', action='store_true', dest='spells',
						help='list spells deserialized from the file ' + SPELL_DB)
	parser.add_argument('--update_voters', action='store_true', dest='update_voters',
						help='get all of the voters that have locked MKR in chief from ' + str(START_BLOCK) + ' - ' + str(END_BLOCK))
	parser.add_argument('--get_interactions', action='store_true', dest='get_interactions',
						help='gets the votes for each voter. Stores them in interactions.obj')
	parser.add_argument('--get_votes_per_frame', action='store_true', dest='get_votes_per_frame',
						help='gets the votes per each frame period (1000 blocks)')
	parser.add_argument('--view_votes_per_frame', action='store_true', dest='view_votes_per_frame',
						help='prints out the votes per 1000 block frame')
	parser.add_argument('--interactions', action='store_true', dest='interactions',
						help='view all of the voting actions sorted by block from interactions.obj')
	parser.add_argument('--make_frames', action='store_true', dest='make_frames',
						help='makes hunderds of pngs to be built into a gif. 1000 blocks per frame')


	global args
	args = parser.parse_args()
	if not args.check:
		modify_provider_address()
	global web3
	if args.test:
		web3 = connect_ws()
	else:
		web3 = connect()
	
	if args.update_spells:
		spells = get_spells()
		filehandler = open(SPELL_DB, 'wb')
		pickle.dump(spells, filehandler)
		sys.exit(0)
	if args.spells:
		list = list_spells()
		list.sort(key=lambda x: x.created)
		for s in list:
			s.display_spell()
		sys.exit(0)
	if args.update_voters:
		vots = get_voters()
		print('\nlist_of_voters:\n')
		print(vots)
		with open(voter_filenam, 'w') as myfile:
			wr = csv.writer(myfile)
			for i in vots:
				wr.writerow([i,])
	if args.get_interactions:
		voters_to_get = voter_filenam
		inters = get_interactions(voter_filenam)
		filehandler = open(INTERACTION_DB, 'wb')
		pickle.dump(inters, filehandler)
		sys.exit(0)
	if args.get_votes_per_frame:
		spells = list_spells()
		spells.sort(key=lambda x: x.created)
		ff = get_vote_frames(spells)
		filehandler = open(VOTE_TALLY_DB, 'wb')
		pickle.dump(ff, filehandler)
		sys.exit(0)
	if args.view_votes_per_frame:
		listv = list_votes()
		listv.sort(key=lambda x: x.blocknum)
		for s in listv:
			s.display_votes()
		sys.exit(0)

	if args.interactions:
		listi = list_interactions()
		listi.sort(key=lambda x: x.block)
		for s in listi:
			s.display_interaction()
		sys.exit(0)
	if args.make_frames:
		inters = list_interactions()
		frams = list_votes()
		print_frames(inters, frams)
		sys.exit(0)



	
	print("Run 'mkr_voting.py --help'")


if __name__ == "__main__":
	main()
























