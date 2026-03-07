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
}
