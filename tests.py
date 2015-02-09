''' 
    Test the TinyPass crypto library for encrypting/decrypting/signing data passed via APIs and webhooks.
'''
import utinypass.crypto
import json


def test_compute_checksum():
    keyvalresults = [
            ( 'k', 'v', 'xdS-GZLVDTtB-aISkvxnoooUhvxkoFF9N_mvhH4HMt4'),
            ( 'aReAlLyShOrTKey', 'v', 'Gm9vbBmm_GP4UChA4AgcXTjSz764eFHI0s-9OMV6EHg'),
            ( 'LongKeyMoRetHaN32ChAraCteRswIllBetRunCatEd', 'v', 'lawYNK0rgNIXRJVUNZk34GVLudTrS6XK-_0u23qQt6U'),
            ( 'exactly32characterkeydonotchange', 'v', 'qEHqACYE1XWUX4TwB2dXuZS75Qs-eo9xdpRRoF_s6l4'),
    ]

    for k,v,r in keyvalresults:
        urlsafe_computed_checksum = utinypass.crypto.compute_checksum( k, v ) 
        assert urlsafe_computed_checksum == r, "Computed checksum for {k}, {v} was {u} not {r}".format(
                k=k, v=v, u=urlsafe_computed_checksum, r=r )



def test_b64encrypt():
    keyvalresults = [
            ( 'k', 'v', 'dg~~~McsStDnPDu7fMaUwdZyOSDy13w8hlSnZYFJnWjcuVBA'),
            ( 'aReAlLyShOrTKey', 'v', 'dg~~~d8xpYoJ45EeXBYz8acMbOc04ywYgqvTpHAxaSb9_ra8'),
            ( 'LongKeyMoRetHaN32ChAraCteRswIllBetRunCatEd', 'v', 'dg~~~ixo0p2u16k1xZ4EORmcxQrkV1ojAtyJ6MiPF3kJFWYM'),
            ( 'exactly32characterkeydonotchange', 'v', 'dg~~~eozlRXGjoYx3zgMaBawz4YH1Sh9-VWUv5T-gzusPPLo'),
    ]
    
    for k,v,r in keyvalresults:
        ciphertext = utinypass.crypto.b64encrypt( k, v )
        assert '~~~' in ciphertext, "Ciphertext appears to be missing the data/checksum delimeter."
        assert ciphertext == r, "Computed cipher text for {k}, {v} was {c} not {r}".format(
                k=k, v=v, c=ciphertext, r=r )



def test_b64decrypt():
    # these values should represent the reverse of the b64encrypt tests.
    keyvalresults = [
            ( 'k', 'dg~~~McsStDnPDu7fMaUwdZyOSDy13w8hlSnZYFJnWjcuVBA', 'v'),
            ( 'aReAlLyShOrTKey', 'dg~~~d8xpYoJ45EeXBYz8acMbOc04ywYgqvTpHAxaSb9_ra8', 'v'),
            ( 'LongKeyMoRetHaN32ChAraCteRswIllBetRunCatEd', 'dg~~~ixo0p2u16k1xZ4EORmcxQrkV1ojAtyJ6MiPF3kJFWYM', 'v'),
            ( 'exactly32characterkeydonotchange', 'dg~~~eozlRXGjoYx3zgMaBawz4YH1Sh9-VWUv5T-gzusPPLo', 'v'),
    ]
    
    for k,v,r in keyvalresults:
        decoded = utinypass.crypto.b64decrypt( k, v )
        assert decoded == r, "Decoded text for {k}, {v} was {d} not {r}".format(
                k=k, v=v, d=decoded, r=r )



def test_tinypass_b64encrypt_decrypt():
    plain = "test"
    ciphertext = utinypass.crypto.b64encrypt('secret', plain)
    #'dGV4dA~~~B2e7u4TkmicXP_lLwvaxFyHbzPZUXxJ4FhorPg0jm_c'
    output = utinypass.crypto.b64decrypt('secret', ciphertext)
    assert plain == output, 'tinypass encrypt -> decrypt cycle failed. {} became {}'.format(
        plain, output)



def test_aesencrypt():
    keyvalresults = [
            ( 'k', 'v', 'RYFS-e7IZOnB4R0R6tgeSA~~~BZ05JZLj_1yg70E65pqfnrid9XhIp1k23J8ajRN282I'),
    ]
    
    for k,v,r in keyvalresults:
        encoded = utinypass.crypto.aesencrypt( k, v )
        assert encoded == r, "Encoded text for {k}, {v} was {e} not {r}".format(
                k=k, v=v, e=encoded, r=r )
        # k v RYFS-e7IZOnB4R0R6tgeSA~~~BZ05JZLj_1yg70E65pqfnrid9XhIp1k23J8ajRN282I



def test_aesdecrypt():
    # these should be the reverse of the test_aesencrypt tests.
    keyvalresults = [
            ( 'k', 'RYFS-e7IZOnB4R0R6tgeSA~~~BZ05JZLj_1yg70E65pqfnrid9XhIp1k23J8ajRN282I', 'v' ),
    ]
    
    for k,v,r in keyvalresults:
        decoded = utinypass.crypto.aesdecrypt( k, v )
        assert decoded == r, "Decoded text for {k}, {v} was {d} not {r}".format(
                k=k, v=v, d=decoded, r=r )



def test_tinypass_rjindael_cycle():
    inp = json.dumps({'my': 'test'})
    data = utinypass.crypto.aesencrypt('BURPm7xRUSH2112IubJwhNgCIe5ccDeaDBeeFxuR', inp)
    outp = utinypass.crypto.aesdecrypt('BURPm7xRUSH2112IubJwhNgCIe5ccDeaDBeeFxuR', data)
    print inp, "-->", data, "-->", outp
    assert inp == outp

if __name__ == '__main__':
    test_tinypass_rjindael_cycle()

