<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Detector;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\DetectorInterface;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\DTO\UploadedFileMetadata;
use Prowendi\HyperfHttpWaf\Enum\RuleAction;
use Prowendi\HyperfHttpWaf\Result\RuleHit;

final class FileUploadDetector implements DetectorInterface
{
    public function detect(RequestContext $context, WafConfig $config): array
    {
        if ($context->files === []) {
            return [];
        }

        $hits = [];

        if (count($context->files) > $config->maxFiles()) {
            $hits[] = new RuleHit(
                ruleId: 'file-count-limit',
                name: 'Uploaded file count exceeded',
                type: 'file',
                target: 'file',
                score: 30,
                action: RuleAction::Score,
                location: 'file',
                matchedSample: (string) count($context->files),
            );
        }

        $totalSize = 0;
        foreach ($context->files as $file) {
            $totalSize += $file->size;
            $this->inspectFile($file, $config, $hits);
        }

        if ($totalSize > $config->maxTotalFileSize()) {
            $hits[] = new RuleHit(
                ruleId: 'file-total-size-limit',
                name: 'Uploaded file total size exceeded',
                type: 'file',
                target: 'file',
                score: 30,
                action: RuleAction::Score,
                location: 'file',
                matchedSample: (string) $totalSize,
            );
        }

        return $hits;
    }

    /**
     * @param list<RuleHit> $hits
     */
    private function inspectFile(UploadedFileMetadata $file, WafConfig $config, array &$hits): void
    {
        if (strlen($file->clientFilename) > $config->maxFilenameLength()) {
            $hits[] = new RuleHit(
                ruleId: 'file-name-length',
                name: 'Uploaded filename too long',
                type: 'file',
                target: 'file',
                score: 20,
                action: RuleAction::Score,
                location: 'file:' . $file->field,
                matchedSample: substr($file->clientFilename, 0, $config->matchedSampleLength()),
            );
        }

        $this->inspectContent($file, $config, $hits);

        $suspicious = $config->suspiciousFileExtensions();
        foreach ($file->allExtensions as $ext) {
            if ($ext !== '' && in_array($ext, $suspicious, true)) {
                $hits[] = new RuleHit(
                    ruleId: 'file-dangerous-extension',
                    name: 'Dangerous uploaded extension',
                    type: 'file',
                    target: 'file',
                    score: 80,
                    action: RuleAction::Block,
                    location: 'file:' . $file->field,
                    matchedSample: $file->clientFilename,
                );
                break;
            }
        }

        if ($file->clientMediaType !== '' && in_array($file->clientMediaType, $config->suspiciousMimeTypes(), true)) {
            $hits[] = new RuleHit(
                ruleId: 'file-dangerous-mime',
                name: 'Dangerous uploaded mime type',
                type: 'file',
                target: 'file',
                score: 80,
                action: RuleAction::Block,
                location: 'file:' . $file->field,
                matchedSample: $file->clientMediaType,
            );
        }
    }

    /**
     * Content sniffing catches webshells behind a clean extension
     * ("profile.jpg" containing "<?php ...") and script payloads inside
     * SVG uploads; the snippet is limited to the first 8 KiB.
     *
     * @param list<RuleHit> $hits
     */
    private function inspectContent(UploadedFileMetadata $file, WafConfig $config, array &$hits): void
    {
        if (! $config->contentInspection() || $file->contentSnippet === '') {
            return;
        }

        if (preg_match('/<\?php\b|<\?=|<%[@!]/i', $file->contentSnippet) === 1) {
            $hits[] = new RuleHit(
                ruleId: 'file-webshell-content',
                name: 'Server-side code inside uploaded file',
                type: 'file',
                target: 'file',
                score: 80,
                action: RuleAction::Block,
                location: 'file:' . $file->field,
                matchedSample: $file->printableHead(),
            );

            return;
        }

        if (preg_match('/^#!.*(\\/bin\\/(?:ba|z|da)?sh|python[23]?|perl|ruby)\\b/im', $file->contentSnippet) === 1) {
            $hits[] = new RuleHit(
                ruleId: 'file-script-shebang',
                name: 'Executable script shebang inside uploaded file',
                type: 'file',
                target: 'file',
                score: 55,
                action: RuleAction::Score,
                location: 'file:' . $file->field,
                matchedSample: $file->printableHead(),
            );

            return;
        }

        if ($file->clientMediaType === 'image/svg+xml'
            && preg_match('/<script\b|on(?:load|error|click|animationbegin)\s*=/i', $file->contentSnippet) === 1
        ) {
            $hits[] = new RuleHit(
                ruleId: 'file-svg-active-content',
                name: 'Active script content inside SVG upload',
                type: 'file',
                target: 'file',
                score: 70,
                action: RuleAction::Block,
                location: 'file:' . $file->field,
                matchedSample: $file->printableHead(),
            );

            return;
        }

        // Zip Slip: archive entries named "../" escape the extraction
        // directory. Entry names are stored in cleartext inside the local
        // file headers, so they appear in the leading snippet.
        if (str_starts_with($file->contentSnippet, "PK\x03\x04")
            && preg_match('~\.\.[/\\\\]~', $file->contentSnippet) === 1
        ) {
            $hits[] = new RuleHit(
                ruleId: 'file-zip-slip',
                name: 'Archive with parent directory traversal entry',
                type: 'file',
                target: 'file',
                score: 65,
                action: RuleAction::Block,
                location: 'file:' . $file->field,
                matchedSample: $file->printableHead(),
            );
        }
    }
}
