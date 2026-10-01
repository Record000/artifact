import random
import string
from datetime import datetime, timedelta
from pyasn1.type import univ
import os
import string

def log(message):
    print(message)

def mutate_octet_string():
    samples = [
        b'',                           
        b'\x12\x34\x56',               
        b'\x00' * 127,                  
        b'\x00' * 128,                  
        b'\x00' * 1024,                
        b'\xFF' * 20,                   
        b'\x00\x01\x02<script>',       
        b'\x30\x03\x02\x01\x05',        
        b'\x12\x34' + b'\xFF' * 100,    
        os.urandom(random.randint(1, 2**16-1))
    ]
    
    mutated = random.choice(samples)
    return mutated

def mutate_IA5_string():
    samples = [
        "",                                     
        "a",                                    
        "A" * 127,                              
        "A" * 128,                              
        "A" * 1024,                             
        "<script>alert(1)</script>",            
        "' OR '1'='1",                          
        "".join(chr(i) for i in range(32)),     
        "".join(random.choices(string.printable, k=64)), 
        os.urandom(random.randint(1, 32)).decode('ascii', errors='ignore')  
    ]

    mutated = random.choice(samples)
    return mutated

def mutate_address_family():
    samples = [
        b'',                        
        b'\x00',                   
        b'\x00\x01',                
        b'\x00\x02',                
        b'\x00\x01\x01',            
        b'\x00\x02\x01',            
        b'\x01\x00',                
        b'\xFF\xFF',                
        b'\x00\xFF',                
        b'\x30\x82',                
        b'\x00\x01\xFF',            
        os.urandom(random.choice([2, 3]))  
    ]
    return random.choice(samples)

def mutate_ip_bitstring():
    samples = [
        b'',                                 #
        b'\x00',                             
        b'\xff\xff\xff\xff',                 
        b'\x00' * 16,                        
        b'\xff' * 17,                       
        os.urandom(16),                     
        bytes([random.getrandbits(8) for _ in range(random.randint(1, 20))])  
    ]
    return random.choice(samples)


def mutate_ip_address_range():
    return [mutate_ip_bitstring(), mutate_ip_bitstring()]

def mutate_ip_address_or_range():
    if random.choice([True, False]):
        return [mutate_ip_bitstring()]
    else:
        return mutate_ip_address_range()

def mutate_ip_address_choice():
    choice = []
    r = random.randint(0, 1)
    if r == 0:
        return None
    else:
        random_length = random.randint(1, 100)
        choice = []
        for i in range(random_length):
            choice += [mutate_ip_address_or_range()]
        return choice

def mutate_bitstring(bitstring: univ.BitString) -> univ.BitString:
    bits = list(bitstring.asBinary())

    mutation_type = random.choice([
        'flip_bit', 'append_bits', 'truncate', 'random_fill', 'replace'
    ])

    if mutation_type == 'flip_bit' and bits:
        index = random.randint(0, len(bits)-1)
        bits[index] = '1' if bits[index] == '0' else '0'

    elif mutation_type == 'append_bits':
        extra_bits = ''.join(random.choices(['0', '1'], k=random.randint(1, 32)))
        bits.extend(extra_bits)

    elif mutation_type == 'truncate' and len(bits) > 1:
        new_len = random.randint(1, len(bits)-1)
        bits = bits[:new_len]

    elif mutation_type == 'random_fill':
        bits = [random.choice(['0', '1']) for _ in range(len(bits))]

    elif mutation_type == 'replace':
        new_len = random.randint(1, 256)
        bits = [random.choice(['0', '1']) for _ in range(new_len)]

    mutated = univ.BitString("'{}'B".format(''.join(bits)))
    return mutated

class OIDMutator:
    def generate_valid_unknown_oid(self, max_components=8):
        first_arc = random.choice([0, 1, 2])
        if first_arc in [0, 1]:
            second_arc = random.randint(0, 39)
        else:
            second_arc = random.randint(0, 9999)

        rest = [str(random.randint(0, 99999)) for _ in range(random.randint(1, max_components - 2))]
        oid = [str(first_arc), str(second_arc)] + rest
        return ".".join(oid)

    def generate_invalid_oid(self):
        mode = random.choice(["empty_element", "oversize_number"])
        
        if mode == "empty_element":
            parts = [str(random.randint(0, 10)) for _ in range(3)]
            parts.insert(random.randint(1, len(parts)), "")
            return ".".join(parts)
        
        elif mode == "oversize_number":
            parts = [str(random.randint(0, 10)) for _ in range(2)]
            parts.append("9" * random.randint(20, 50))
            return ".".join(parts)


    def mutate_oid(self):
        return self.generate_valid_unknown_oid()


class BasicConstraintsMutator():
    def __init__(self, oid, critical, value):
        self.oid = oid
        self.critical = critical
        self.value = value
        
    def mutate(self):
        if random.random() < 0.5:
            try:
                oid_mutator = OIDMutator() 
                self.oid = oid_mutator.mutate_oid()
            except NameError:
                pass

        if random.random() < 0.5:
            self.critical = random.choice([True, False])

        if random.random() < 0.5:
            random_length = random.randint(1, 100) 
            # print("random_length:", random_length)
            
            self.value = []
            
            for i in range(random_length):
                rand_type = random.random()
                
                if rand_type < 0.45:
                    self.value.append(random.randint(0, 2**16-1))
                
                elif rand_type < 0.9:
                    self.value.append(random.choice([True, False]))
                
                else:
                    octet_len = random.randint(1, 50)
                    random_bytes = bytes([random.randint(0, 255) for _ in range(octet_len)])
                    self.value.append(random_bytes)

        return self.oid, self.critical, self.value

class KeyIdentifierMutator():
    def __init__(self, oid, critical, value):
        self.oid = oid
        self.critical = critical
        self.value = value
    def mutate(self):
        if random.random() < 0.5:
            oid_mutator = OIDMutator()
            self.oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:
            self.critical = random.choice([True, False])
        if random.random() < 0.5:
            self.value = mutate_octet_string()
        return self.oid, self.critical, self.value

class AuthorityKeyIdentifierMutator():
    def __init__(self, oid, critical, value:list):
        self.oid = oid
        self.critical = critical
        self.value = value
    def mutate(self):
        if random.random() < 0.5:
            oid_mutator = OIDMutator()
            self.oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:
            self.critical = random.choice([True, False])
        if random.random() < 0.5:
            random_length = random.randint(1, 200)
            # print("random_length:", random_length)
            self.value = []
            for i in range(random_length):
                self.value += [mutate_octet_string()]
        return self.oid, self.critical, self.value

class KeyUsageMutator():
    def __init__(self, oid, critical, value:list):
        self.oid = oid
        self.critical = critical
        self.value = value
    def mutate(self):
        # if random.random() < 0.5:
        #     oid_mutator = OIDMutator()
        #     self.oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:
            self.critical = random.choice([True, False])
        if random.random() < 0.5:
            random_length = random.randint(1, 50)
            # print("random_length:", random_length)
            self.value = ""
            for i in range(random_length):
                self.value += str(random.choice([0, 1]))
        return self.oid, self.critical, self.value

class CrlDistributionPointsMutator():
    # CRLDistributionPoints：univ.SequenceOf DistributionPoint
    # class DistributionPoint(univ.Sequence):
    # DistributionPoint.componentType = namedtype.NamedTypes(
    #     namedtype.OptionalNamedType('distributionPoint', DistributionPointName().subtype(
    #         implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
    #     namedtype.OptionalNamedType('reasons', ReasonFlags().subtype(
    #         implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    #     namedtype.OptionalNamedType('cRLIssuer', GeneralNames().subtype(
    #         implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
    # )
    def __init__(self, oid, critical, value:list):
        self.oid = oid
        self.critical = critical
        self.value = value
    def mutate(self):
        if random.random() < 0.5:
            oid_mutator = OIDMutator()
            self.oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:
            self.critical = random.choice([True, False])
        if random.random() < 0.5:
            random_length = random.randint(1, 100)
            if random.random() < 0.5:
                self.value = []
            for i in range(random_length):
                self.value += [[mutate_IA5_string()]]
        return self.oid, self.critical, self.value

class AuthorityInformationAccessMutator():
    def __init__(self, oid, critical, value:list):
        self.oid = oid
        self.critical = critical
        self.value = value
    def mutate(self):
        if random.random() < 0.5:
            oid_mutator = OIDMutator()
            self.oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:
            self.critical = random.choice([True, False])
        if random.random() < 0.5:
            random_length = random.randint(1, 200)
            if random.random() < 0.5:
                self.value = []
            for i in range(random_length):
                oid_mutator = OIDMutator()
                access_method = oid_mutator.mutate_oid()
                access_location = random.choice([mutate_IA5_string(), mutate_octet_string()])
                self.value += [[access_method, access_location]]
        return self.oid, self.critical, self.value

class SubjectInformationAccessMutator():
    def __init__(self, oid, critical, value:list):
        self.oid = oid
        self.critical = critical
        self.value = value
    def mutate(self):
        if random.random() < 0.5:
            oid_mutator = OIDMutator()
            self.oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:
            self.critical = random.choice([True, False])
        if random.random() < 0.5:
            random_length = random.randint(1, 200)
            if random.random() < 0.5:
                self.value = []
            for i in range(random_length):
                oid_mutator = OIDMutator()
                access_method = oid_mutator.mutate_oid()
                access_location = random.choice([mutate_IA5_string(), mutate_octet_string()])
                self.value += [[access_method, access_location]]
        return self.oid, self.critical, self.value

class CertificatePolicyMutator():
    def __init__(self, oid, critical, value:list):
        self.oid = oid
        self.critical = critical
        self.value = value
    def mutate(self):
        if random.random() < 0.5:
            oid_mutator = OIDMutator()
            self.oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:
            self.critical = random.choice([True, False])
        if random.random() < 0.5:
            random_length = random.randint(1, 200)
            if random.random() < 0.5:
                self.value = []
            oid_mutator = OIDMutator()
            for i in range(random_length):
                self.value += [oid_mutator.mutate_oid()]
        return self.oid, self.critical, self.value

class IPAddrsBlockMutator():
    def __init__(self, oid, critical, value:list):
        self.oid = oid
        self.critical = critical
        self.value = value
    def mutate(self):
        if random.random() < 0.5:
            oid_mutator = OIDMutator()
            self.oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:
            self.critical = random.choice([True, False])
        random_length = random.randint(1, 2)
        self.value = []
        for i in range(random_length):
            self.value += [[mutate_address_family(),mutate_ip_address_choice()]]
        return self.oid, self.critical, self.value

class AsIdMutator():
    def __init__(self, oid, critical, value:list):
        self.oid = oid
        self.critical = critical
        self.value = value
    def mutate(self):
        if random.random() < 0.5:

            oid_mutator = OIDMutator()
            self.oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:

            self.critical = random.choice([True, False])

        random_length = random.randint(1, 100)
        self.value = []
        for i in range(random_length):
            if random.random() < 0.5:
                self.value += [[random.randint(-2**48, 2**48-1), random.randint(-2**48, 2**48-1)]]
            else:
                self.value += [[random.randint(-2**48, 2**48-1)]]
        return self.oid, self.critical, self.value

def generate_random_validity():
    is_generalized = random.choice([True, False])
    
    if is_generalized:
        base_year = random.randint(2050, 9999)
        time_format = "%Y%m%d%H%M%SZ"
    else:
        base_year = random.randint(1950, 2049)
        time_format = "%y%m%d%H%M%SZ"

    base_date = datetime(base_year, random.randint(1, 12), random.randint(1, 28),
                         random.randint(0, 23), random.randint(0, 59), random.randint(0, 59))
    while True:
        try:
            delta_days = random.randint(0, 365 * 50)
            not_before = base_date
            not_after = base_date + timedelta(days=delta_days)
            break
        except:
            continue

    return not_before.strftime(time_format), not_after.strftime(time_format)


class CertMutator:
    def __init__(self, mutate_type):
        self.mutate_type = mutate_type
    
    def mutate_version(self, version):
        # legal versions are 2
        # mutate to 0, 1, negative, or random
        
        tmp = random.random()
        mutated_version = None
        if tmp < 0.3:
            mutated_version = -1
        elif tmp < 0.45:
            mutated_version = 1
        elif tmp < 0.6:
            mutated_version = 0
        else:
            mutated_version = random.randint(2, 2**31-1)
        log("mutated_version:" + str(mutated_version))
        return mutated_version
    
    def mutate_serialnum(self, peers:list):
        tmp = random.random()
        mutated_serialnum = None
        if tmp < 0.3:
            mutated_serialnum = random.randint(-2**31, 0)
        if tmp < 0.6:
            # return random.randint(2**160, 2**320)
            mutated_serialnum = random.randint(2**160, 2**320)
        elif tmp < 0.9:
            # return random.randint(-2**320, -2**160)
            mutated_serialnum = random.randint(-2**320, -2**160)
        else:
            # return random.choice(peers) 
            mutated_serialnum = random.choice(peers)
        log("mutated_serialnum:" + str(mutated_serialnum))
        return mutated_serialnum
    
    def mutate_signature(self):
        oid_mutator = OIDMutator()
        mutated_oid = oid_mutator.mutate_oid()
        log("mutated_signature:" + str(mutated_oid))
        return mutated_oid
    
    def mutate_issuer(self):
        return 
    
    def mutate_subject(self):
        return
    
    def mutate_validity(self):
        before, after = generate_random_validity()
        log("mutated_validity:" + str(before) + " " + str(after))
        return before, after
    
    def mutate_subjectPublicKeyInfo(self, n, e, oid, public_key_bitstring):
        if random.random() < 0.5:
            # mutate n
            n = random.randint(2**160, 2**320)
        if random.random() < 0.5:
            # mutate e
            e = random.randint(2**160, 2**320)
        if random.random() < 0.5:
            # mutate oid
            oid_mutator = OIDMutator()
            oid = oid_mutator.mutate_oid()
        if random.random() < 0.5:
            # mutate public_key_bitstring
            public_key_bitstring = mutate_bitstring(public_key_bitstring)
        return n, e, oid, public_key_bitstring
        
    def mutate_basic_constraints(self, oid, critical, value):
        mutator = BasicConstraintsMutator(oid, critical, value)
        mutated_oid, mutated_critical, mutated_value = mutator.mutate()
        #print("oid:", oid)
        #print("critical:", critical)
        #print("value:", value)
        #print("mutated_oid:", mutated_oid)
        #print("mutated_critical:", mutated_critical)
        #print("mutated_value:", mutated_value)
        return mutated_oid, mutated_critical, mutated_value
    
    def mutate_key_identifier(self, oid, critical, value):
        mutator = KeyIdentifierMutator(oid, critical, value)
        return mutator.mutate()
    
    def mutate_authority_key_identifier(self, oid, critical, value):
        mutator = AuthorityKeyIdentifierMutator(oid, critical, value)
        return mutator.mutate()
    
    def mutate_key_usage(self, oid, critical, value):
        mutator = KeyUsageMutator(oid, critical, value)
        mutated_oid, mutated_critical, mutated_value = mutator.mutate()
        return mutated_oid, mutated_critical, mutated_value
    
    def mutate_crl_distribution_points(self, oid, critical, value):
        mutator = CrlDistributionPointsMutator(oid, critical, value)
        return mutator.mutate()
    
    def mutate_authority_information_access(self, oid, critical, value):
        mutator = AuthorityInformationAccessMutator(oid, critical, value)
        return mutator.mutate()

    def mutate_subject_information_access(self, oid, critical, value):
        mutator = SubjectInformationAccessMutator(oid, critical, value)
        return mutator.mutate()

    def mutate_certificate_policies(self, oid, critical, value):
        mutator = CertificatePolicyMutator(oid, critical, value)
        return mutator.mutate()
    
    def mutate_ip_address(self, oid, critical, value):
        mutator = IPAddrsBlockMutator(oid, critical, value)
        return mutator.mutate()

    def mutate_as_id(self, oid, critical, value):
        mutator = AsIdMutator(oid, critical, value)
        return mutator.mutate()

