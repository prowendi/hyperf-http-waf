<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\DTO\FlattenedPayload;
use Prowendi\HyperfHttpWaf\DTO\TextInput;
use JsonSerializable;
use Stringable;

final class InputFlattener
{
    public function flatten(mixed $payload, string $location, int $maxDepth): FlattenedPayload
    {
        $inputs = [];
        $count = 0;
        $depth = 0;
        $maxValueLength = 0;

        $this->walk($payload, $location, '', 1, max(1, $maxDepth), $inputs, $count, $depth, $maxValueLength);

        return new FlattenedPayload($inputs, $count, $depth, $maxValueLength);
    }

    /**
     * @param list<TextInput> $inputs
     */
    private function walk(
        mixed $payload,
        string $location,
        string $path,
        int $currentDepth,
        int $maxDepth,
        array &$inputs,
        int &$count,
        int &$depth,
        int &$maxValueLength,
    ): void {
        $depth = max($depth, $currentDepth);

        if (is_array($payload)) {
            if ($payload === []) {
                return;
            }

            if ($currentDepth >= $maxDepth) {
                $this->appendInput($location, $path === '' ? $location : $path, $this->stringify($payload), $inputs, $count, $maxValueLength);
                return;
            }

            foreach ($payload as $key => $value) {
                $nextPath = $path === '' ? (string) $key : $path . '.' . $key;
                $this->walk($value, $location, $nextPath, $currentDepth + 1, $maxDepth, $inputs, $count, $depth, $maxValueLength);
            }

            return;
        }

        if (is_object($payload)) {
            if ($payload instanceof JsonSerializable) {
                $this->walk($payload->jsonSerialize(), $location, $path, $currentDepth, $maxDepth, $inputs, $count, $depth, $maxValueLength);
                return;
            }

            if ($payload instanceof Stringable) {
                $this->appendInput($location, $path === '' ? $location : $path, (string) $payload, $inputs, $count, $maxValueLength);
            }

            return;
        }

        if ($payload === null) {
            return;
        }

        $this->appendInput($location, $path === '' ? $location : $path, $this->stringify($payload), $inputs, $count, $maxValueLength);
    }

    /**
     * @param list<TextInput> $inputs
     */
    private function appendInput(
        string $location,
        string $name,
        string $value,
        array &$inputs,
        int &$count,
        int &$maxValueLength,
    ): void {
        $count++;
        $maxValueLength = max($maxValueLength, strlen($value));
        $inputs[] = new TextInput($location, $name, $value);
    }

    private function stringify(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_scalar($value)) {
            return (string) $value;
        }

        $encoded = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (is_string($encoded)) {
            return $encoded;
        }

        return '[unserializable]';
    }
}
