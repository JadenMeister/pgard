<!-- corpus: expect=low -->
<template>
  <div v-html="clean"></div>
</template>
<script setup lang="ts">
import DOMPurify from "isomorphic-dompurify";
import { computed } from "vue";
const props = defineProps<{ source: string }>();
const clean = computed(() => {
  return DOMPurify.sanitize(props.source, { USE_PROFILES: { html: true } });
});
</script>
