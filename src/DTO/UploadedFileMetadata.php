<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\DTO;

use Psr\Http\Message\UploadedFileInterface;
use Throwable;

final readonly class UploadedFileMetadata
{
    private const CONTENT_SNIPPET_LENGTH = 8192;

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
        public string $contentSnippet = '',
    ) {
    }

    public static function fromUploadedFile(string $field, UploadedFileInterface $file, bool $readContent = true): self
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
            $readContent ? self::readContentSnippet($file) : '',
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
            'content_head' => $this->printableHead(),
        ];
    }

    /**
     * Reads the first bytes of the upload so detectors can recognize
     * webshells hiding behind a clean extension ("shell.php" renamed to
     * "profile.jpg"). Only seekable streams are probed: reading a
     * non-seekable stream is destructive and would corrupt the upload
     * for the business handler. The position is always restored.
     */
    private static function readContentSnippet(UploadedFileInterface $file): string
    {
        try {
            $stream = $file->getStream();

            if (! $stream->isSeekable()) {
                return '';
            }

            $position = $stream->tell();
            $stream->rewind();
            $snippet = $stream->read(self::CONTENT_SNIPPET_LENGTH);
            $stream->seek($position);

            return $snippet;
        } catch (Throwable) {
            return '';
        }
    }

    public function printableHead(): string
    {
        if ($this->contentSnippet === '') {
            return '';
        }

        $printable = preg_replace('~[^\x20-\x7e]+~', ' ', substr($this->contentSnippet, 0, 64));

        return is_string($printable) ? trim($printable) : '';
    }
}
