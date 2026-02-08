
# [TA]   -> [LCA]
# [LCA]  -> [DCA][MFT][CAs][ROAs][CRL]
# [CAs]  -> [LCA][CAs]|ε
# [ROAs] -> [ROA][ROAs]|ε 

# S -> [TA]
# [TA]  -> [LCA]
# [LCA]  -> [DCA] [MFT] [CAs] [ROAs] [CRL]
# [CAs]  -> ε | [LCA] [CAs]
# [ROAs] -> ε | [ROA] [ROAs]
import nltk
from nltk import CFG
import random

rpki_grammar = CFG.fromstring("""
    start -> ta
    ta -> lca
    lca -> DCA MFT cas roas CRL
    cas -> lca cas | 
    roas -> ROA roas | 
    
    DCA -> 'DCA'
    MFT -> 'MFT'
    CRL -> 'CRL'
    ROA -> 'ROA'
""")

def rederive_cas():
    if random.random() < 0.5:
        return rederive_lca() + rederive_cas() 
    else:
        return []

def rederive_roas():
    if random.random() < 0.5:
        return ['ROA'] + rederive_roas()
    else:
        return []

def rederive_lca():
    return ['DCA', 'MFT'] + rederive_cas() + rederive_roas() + ['CRL']

def rederive_single_lca(dca_index):
    return rederive_lca()

def find_corresponding_crl(sentence, dca_index):
    stack = []
    for i, token in enumerate(sentence):
        if token == 'DCA':
            stack.append(i)  
        elif token == 'CRL':
            dca_idx = stack.pop()  
            if dca_idx == dca_index:
                return i  
    return -1  

def mutator(sentence, dca_index):
    crl_index = find_corresponding_crl(sentence, dca_index)
    assert crl_index != -1, 
    
    new_lca = rederive_single_lca(dca_index)
    
    new_sentence = sentence[:dca_index] + new_lca + sentence[crl_index+1:]
    return new_sentence

parser = nltk.ChartParser(rpki_grammar, trace=2)

test_sentence = ['DCA', 'MFT', 'DCA', 'MFT', 'ROA', 'CRL', 'CRL']

print("origin:", test_sentence)
dca_index = 0

print("before mutation:", test_sentence)
new_sentence = mutator(test_sentence, dca_index)
print("after mutation:", new_sentence)

for tree in parser.parse(test_sentence):
    tree.pretty_print()

for tree in parser.parse(test_sentence):
    tree.pretty_print()


    
    