import json
import random
import sys

INITIAL_GROUP_SIZE = 100
MAX_GROUP_SIZE = 200
MIN_GROUP_SIZE = 1

NUM_COMMITS = 100
P_EXTERNAL = 0.1
P_RESYNC = 0.5

MAX_ADDS = 20
MAX_FRAC_UPDATES = 0.4
MAX_FRAC_REMOVES = 0.4

# Phase 1: Build the initial group
# ... using a blend of:
# * add-by-reference
# * add-by-value
# * external-join

# For each commit:
# * Create logical proposals
#   * Create a set of new added members
#   * Identify a set of removed members
#   * Identify a set of updated members from among those not being removed
#   * ... making sure to leave at least one non-updated, non-removed member to commit
#
# * Divide add/remove commits into by-reference and by-value (udpate is always by-reference)
# * For each add / remove commit by value:
#   * Choose a random proposer 
#   * Generate proposal
# * Choose a random committer from among the non-updated, non-removed members
# * Commit all the proposals

def coin(p):
    return random.random() <= p

def addProposal(key_package_index):
    return { "proposalType": "add", "keyPackage": key_package_index }

def removeProposal(removed):
    return { "proposalType": "remove", "removed": removed }

class RandomSession:
    # Create an initial group in a single commit
    # TODO: Make this a blend of:
    # * Add proposed by member, committed by member
    # * Add proposed by joiner, committed by member
    # * External join
    def __init__(self, initial_size):
        self.actors = set()
        self.script = []
        self.next_actor_index = 0
 
        creator = self.next_actor()
        self.script.append({ "action": "createGroup", "actor": creator })

        joiners = [self.next_actor() for _ in range(1, initial_size)]
        for joiner in joiners:
            self.script.append({ "action": "createKeyPackage", "actor": joiner })

        byValue = [addProposal(i) for i in range(1, initial_size)]
        self.script.append({
            "action": "fullCommit",
            "actor": creator,
            "byValue": byValue,
            "joiners": joiners,
        })

        self.actors.add(creator)
        self.actors |= set(joiners)
    
    def next_actor(self):
        n = self.next_actor_index
        self.next_actor_index += 1
        return "actor{}".format(n)

    def random_step(self):
        if coin(P_EXTERNAL):
            resync = coin(P_RESYNC)
            self.external_commit_step(resync)
            return
        self.commit_step()

    def external_commit_step(self, resync):
        joiner = random.choice(list(self.actors)) if resync else self.next_actor()

        eligible_adders = self.actors - set([joiner])
        adder = random.choice(list(eligible_adders))
        members = eligible_adders - set([adder])

        self.script.append({
            "action": "externalJoin",
            "actor": adder,
            "joiner": joiner,
            "removePrior": resync,
            "members": list(members),
        })

        if not resync:
            self.actors.add(joiner)

    def commit_step(self):
        # Decide how many of which types of proposal to commit
        # TODO: Include other types of proposal 
        n_members = len(self.actors)
        n_add = random.randint(0, min(MAX_ADDS, MAX_GROUP_SIZE - n_members))
        n_remove = random.randint(0, int(MAX_FRAC_REMOVES * n_members))
        n_update = random.randint(0, int(MAX_FRAC_UPDATES * n_members))

        # Decide where to take each action
        joiners = [self.next_actor() for _ in range(n_add)]
        leavers = random.sample(list(self.actors), n_remove)
        remainers = self.actors - set(leavers)
        updaters = random.sample(list(remainers), n_update)
        eligible_committers = remainers - set(updaters)
        
        # Create Update proposals
        byReference = list(range(len(self.script), len(self.script) + n_update) )
        for actor in updaters:
            self.script.append({ "action": "updateProposal", "actor": actor })

        # Create KeyPackages
        keyPackages = list(range(len(self.script), len(self.script) + n_add))
        for joiner in joiners:
            self.script.append({ "action": "createKeyPackage", "actor": joiner })

        # Create proposal descriptions for Adds and Removes
        # TODO: Commit some of these by reference
        addsByValue = [addProposal(i) for i in keyPackages]
        removesByValue = [removeProposal(actor) for actor in leavers]
        byValue = addsByValue + removesByValue

        # Commit the proposals
        committer = random.choice(list(eligible_committers))
        self.script.append({
            "action": "fullCommit",
            "actor": committer,
            "byValue": byValue,
            "byReference": byReference,
            "joiners": joiners,
            "members": list(remainers - set([committer]))
        })

        # Update membership tracking
        self.actors = remainers | set(joiners)

    def dump(self):
        config = { "scripts": { "random": self.script } }
        print(json.dumps(config, indent = 2))

#seed = random.randint(0, sys.maxsize)
seed = 1170625869743070381
# print("Starting random tests with rand seed {}".format(seed))
random.seed(seed)

g = RandomSession(5)

for _ in range(NUM_COMMITS):
    g.random_step()

g.dump();
