<!-- corpus: expect=PG-XSS-003 -->
<template>
  <div v-html="rendered"></div>
</template>
<script setup>
import { computed } from "vue";
const props = defineProps({ markdown: String });
const rendered = computed(() => props.markdown.replace(/\n/g, "<br>"));
</script>
