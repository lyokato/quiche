const startedAt = performance.now();

/**
 * @param {{ hostname: string, port: number }} args
 * @param {{ serverCertificateHashes: Array<{ algorithm: string, value: string }> }} hashes
 */
async function startClientTests(args, hashes) {
    const url = 'https://' + args.hostname + ':' + args.port + '/echo'
    console.log('startconnection123')
    const hashargs = {
        ...hashes,
        serverCertificateHashes: hashes.serverCertificateHashes
            .map(({ algorithm, value }) => {
                let bytes = value.split(':').map((el) => parseInt(el, 16));
                let u8Array = new Uint8Array(bytes.length);
                bytes.forEach((v, i) => u8Array[i] = v);

                return {
                    algorithm,
                    value: u8Array,
                }
            })
    }
    // eslint-disable-next-line no-undef
    console.log('hashagrs', hashargs)
    const transport = new WebTransport(url, hashargs)
    transport.closed
        .then(() => {
            console.log('The HTTP/3 connection to ', url, 'closed gracefully.')
        })
        .catch((error) => {
            console.error(
                'The HTTP/3 connection to',
                url,
                'closed due to ',
                error,
                '.'
            )
        })

    await transport.ready
    console.log('webtransport is ready', transport, (performance.now() - startedAt).toFixed(1), "ms")
    await echoTestsConnection(transport)
}

async function echoTestsConnection(transport) {
    // some echo tests for testing the webtransport library, not for production
    const stream = await transport.createBidirectionalStream()
    const writer = stream.writable.getWriter()
    console.log('stream opened', (performance.now() - startedAt).toFixed(1), "ms")
    const data1 = new Uint8Array([65, 66, 67])
    const data2 = new Uint8Array([68, 69, 70])
    writer.write(data1)
    console.log('data sent', (performance.now() - startedAt).toFixed(1), "ms")
    writer.write(data2)
    console.log('data sent', (performance.now() - startedAt).toFixed(1), "ms")
    const reader = stream.readable.getReader()
    let i = data1.length + data2.length
    let pos = 0
    const refArray1 = new Uint8Array(i)
    refArray1.set(data1)
    refArray1.set(data2, data1.length)

    const resultArray1 = new Uint8Array(i)
    console.log('TEST 1: start')

    while (true && i > 0) {
        const { done, value } = await reader.read()
        if (done) {
            break
        }
        const decoder = new TextDecoder();
        const view = decoder.decode(value);

        // value is a Uint8Array
        console.log('incoming bidi stream', view, Date.now())

        resultArray1.set(value, pos)
        i -= value.length
        pos += value.length
    }
    console.log('all bidi received, next close writer', (performance.now() - startedAt).toFixed(1), "ms")

    const decoder = new TextDecoder();
    const view = decoder.decode(resultArray1);
    console.log(`Final value received from server: ${view}`);

    try {
        await writer.close()
        console.log('All data has been sent.')
    } catch (error) {
        console.error(`An error occurred: ${error}`)
        throw new Error('outgoing bidi stream test failed')
    }
    console.log('next close reader')
    try {
        await reader.cancel(0)
        console.log('All data has been read.')
    } catch (error) {
        console.error(`An error occurred: ${error}`)
        throw new Error('outgoing bidi stream test failed')
    }
}



window.onFingerprintSubmit = () => {
    let fingerprint = document.getElementById("fingerprint").value.trim();
    console.log(`fingerprint: "${fingerprint}"`)

    startClientTests(
        { hostname: '127.0.0.1', port: 4430 },
        {
            serverCertificateHashes: [
                {
                    algorithm: 'sha-256',
                    value: fingerprint,
                },
            ]
        }
    )
}
