<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\DTO;

use Psr\Http\Message\UploadedFileInterface;

final readonly class UploadedFileMetadata
{
    /**
     * @param list<string> $allExtensions
     */
    public function __construct(
        public string $field,
        public string $clientFilename,
        public string $extension,
        public array $allExtensions,
        public string $clientMediaType,
        public int $size,
    ) {
    }

    public static function fromUploadedFile(string $field, UploadedFileInterface $file): self
    {
        $filename = (string) ($file->getClientFilename() ?? '');
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        $parts = explode('.', $filename);
        array_shift($parts);
        $allExtensions = array_values(array_map('strtolower', $parts));

        return new self(
            $field,
            $filename,
            $extension,
            $allExtensions,
            strtolower((string) ($file->getClientMediaType() ?? '')),
            max(0, (int) ($file->getSize() ?? 0)),
        );
    }

    public function toArray(): array
    {
        return [
            'field' => $this->field,
            'client_filename' => $this->clientFilename,
            'extension' => $this->extension,
            'all_extensions' => $this->allExtensions,
            'client_media_type' => $this->clientMediaType,
            'size' => $this->size,
        ];
    }
}
