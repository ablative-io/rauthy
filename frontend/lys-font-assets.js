/** Emit font encodings required by Rauthy's embedded static-asset handler. */
import { brotliCompressSync, gzipSync } from 'node:zlib';

/** @returns {import('vite').Plugin} */
export function lysFontAssets() {
    return {
        name: 'lys-font-encodings',
        generateBundle(options, bundle) {
            for (const asset of Object.values(bundle)) {
                if (asset.type !== 'asset' || !asset.fileName.endsWith('.ttf')) continue;
                this.emitFile({
                    type: 'asset',
                    fileName: asset.fileName + '.br',
                    source: brotliCompressSync(asset.source),
                });
                this.emitFile({
                    type: 'asset',
                    fileName: asset.fileName + '.gz',
                    source: gzipSync(asset.source),
                });
            }
        },
    };
}
