<!-- corpus: expect=none -->
<template>
  <div v-html="DOMPurify.sanitize(html)"></div>
</template>
<script setup>
import DOMPurify from "dompurify";
defineProps({ html: String });
</script>
